from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
import sqlite3
from typing import Any
from urllib.parse import unquote, urlsplit

from quant_hub.config import Settings
from quant_hub.ids import new_public_id, object_id_for_sha256, sha256_hex, stable_sha256
from quant_hub.platform.db import connect_database, immediate_transaction, utc_now
from quant_hub.platform.objects import ObjectStore
from quant_hub.platform.releases import (
    ReleaseAuthority,
    ReleaseCandidateSpec,
    ReleaseCertificate,
)
from quant_hub.platform.workflow import canonical_json, register_verified_object
from quant_hub.presentation import ArchivePresentation, InternalArchiveLink
from quant_hub.presentation.chapters import (
    ArchiveChapter,
    ArchiveChapterManifestError,
    ArchiveChapterManifests,
)

from .contracts import ArchiveDocumentInput, ArchiveReleaseInput
from .database import archive_connection, initialize_archive_database
from .markdown import MarkdownProjection, TocEntry, project_markdown
from .service import ingest_archive_snapshot, initialize_platform
from .source_reader import ReadOnlyArchiveAssetSource, validate_archive_relative_path


class ArchiveMappingConflict(RuntimeError):
    pass


class ArchiveNotFound(KeyError):
    pass


@dataclass(frozen=True, slots=True)
class PreparedArchiveDocument:
    spec: ArchiveDocumentInput
    object_id: str
    source_location_id: str
    source_origin_uri: str
    source_observed_at: str
    source_bytes: bytes
    projection: MarkdownProjection
    rendered_object_id: str
    validation_manifest_hash: str


@dataclass(frozen=True, slots=True)
class PublishedArchiveRelease:
    research_id: str
    research_release_id: str
    activation_id: str | None
    active_revision: int | None
    document_version_ids: tuple[str, ...]
    document_manifest_hash: str
    candidate_spec: ReleaseCandidateSpec
    created: bool


def _toc_row(entry: TocEntry) -> dict[str, Any]:
    return {
        "anchor_id": entry.anchor_id,
        "title_text": entry.title_text,
        "level": entry.level,
        "children": [_toc_row(child) for child in entry.children],
    }


def _object_id_from_urn(value: str) -> str:
    prefix = "qrh:object:"
    if not value.startswith(prefix):
        raise ValueError("object URN is not canonical")
    object_id = value[len(prefix) :]
    if object_id != object_id_for_sha256(object_id.removeprefix("obj_sha256_")):
        raise ValueError("object URN does not contain a canonical content ID")
    return object_id


class ArchiveCatalog:
    """Archive 研究、不可变版本、release、页面和搜索的领域服务。"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.object_store = ObjectStore(settings.object_root)
        self.presentation = ArchivePresentation.default()
        self.chapter_manifests = ArchiveChapterManifests.default()
        self._archive_link_index_cache: dict[str, dict[str, Any]] | None = None

    def initialize(self) -> dict[str, list[int]]:
        applied = {
            "platform": initialize_platform(self.settings),
            "archive": initialize_archive_database(self.settings),
        }
        # D-05 Python backfill is an explicit initialization/migration action,
        # never a side effect of a homepage or history GET.
        from quant_hub.collaboration.service import ArchiveCollaboration

        ArchiveCollaboration(self.settings).backfill_research_updates()
        return applied

    def _source_record(self, source_location_id: str) -> tuple[str, str]:
        connection = connect_database(self.settings.database_path)
        try:
            row = connection.execute(
                "SELECT origin_uri,observed_at FROM source_location WHERE source_location_id=?",
                (source_location_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise RuntimeError("registered source location disappeared")
        return str(row["origin_uri"]), str(row["observed_at"])

    def _prepare_document(self, spec: ArchiveDocumentInput) -> PreparedArchiveDocument:
        registration = ingest_archive_snapshot(self.settings, spec.source_path)
        source_bytes = self.object_store.read_bytes(registration.object_id)
        source_origin_uri, source_observed_at = self._source_record(
            registration.source_location_id
        )
        actual_digest = registration.object_id.removeprefix("obj_sha256_")
        approved = (
            spec.approved_origin_uri,
            spec.approved_object_urn,
            spec.approved_content_sha256,
            spec.approved_bytes,
        )
        actual = (
            source_origin_uri,
            f"qrh:object:{registration.object_id}",
            actual_digest,
            len(source_bytes),
        )
        if actual != approved:
            raise ArchiveMappingConflict(
                "current Archive bytes do not match the approved discovery identity"
            )
        projection = project_markdown(source_bytes)
        if projection.document_sha256 != registration.object_id.removeprefix("obj_sha256_"):
            raise RuntimeError("Markdown projection input identity differs from registered source")
        rendered = self.object_store.put_bytes(projection.rendered_html.encode("utf-8"))
        platform = connect_database(self.settings.database_path)
        try:
            register_verified_object(
                platform,
                rendered,
                self.object_store,
                media_type="text/html; charset=utf-8",
            )
        finally:
            platform.close()
        validation_manifest_hash = stable_sha256(
            "archive-document-projection/v1",
            projection.projector_version,
            projection.document_sha256,
            rendered.object_id,
            str(len(projection.headings)),
            str(len(projection.math_nodes)),
            sha256_hex(projection.plain_text.encode("utf-8")),
        )
        return PreparedArchiveDocument(
            spec=spec,
            object_id=registration.object_id,
            source_location_id=registration.source_location_id,
            source_origin_uri=source_origin_uri,
            source_observed_at=source_observed_at,
            source_bytes=source_bytes,
            projection=projection,
            rendered_object_id=rendered.object_id,
            validation_manifest_hash=validation_manifest_hash,
        )

    @staticmethod
    def _summary_artifact(release: ArchiveReleaseInput) -> tuple[bytes, str] | None:
        if release.summary is None:
            return None
        assert release.summary_provenance_urn is not None
        payload = canonical_json(
            {
                "schema_version": "archive-release-summary/v1",
                "summary": release.summary,
                "summary_sha256": sha256_hex(release.summary.encode("utf-8")),
                "provenance_kind": "source_object",
                "provenance_urn": release.summary_provenance_urn,
                "authorship": "unspecified_provided_annotation",
                "verification": "pending_release_review",
            }
        ).encode("utf-8")
        digest = sha256_hex(payload)
        return payload, f"qrh:object:{object_id_for_sha256(digest)}"

    def _prepare_summary_artifact(self, release: ArchiveReleaseInput) -> str | None:
        artifact = self._summary_artifact(release)
        if artifact is None:
            return None
        payload, expected_urn = artifact
        stored = self.object_store.put_bytes(payload)
        if f"qrh:object:{stored.object_id}" != expected_urn:
            raise RuntimeError("summary artifact content identity is inconsistent")
        platform = connect_database(self.settings.database_path)
        try:
            register_verified_object(
                platform,
                stored,
                self.object_store,
                media_type="application/vnd.qrh.archive-summary+json; charset=utf-8",
            )
        finally:
            platform.close()
        return expected_urn

    @staticmethod
    def _candidate_spec(
        release: ArchiveReleaseInput,
        prepared: tuple[PreparedArchiveDocument, ...],
    ) -> tuple[ReleaseCandidateSpec, dict[str, Any]]:
        ordered = sorted(
            prepared,
            key=lambda item: (item.spec.sort_key, item.spec.document_slug),
        )
        if release.summary_provenance_urn is not None:
            source_objects = {f"qrh:object:{item.object_id}" for item in prepared}
            if release.summary_provenance_urn not in source_objects:
                raise ArchiveMappingConflict(
                    "summary provenance must be an exact source object in this release"
                )
        summary_artifact = ArchiveCatalog._summary_artifact(release)
        summary_artifact_urn = summary_artifact[1] if summary_artifact else None
        manifest_payload = {
            "schema_version": "archive-release-manifest/v2",
            "research_slug": release.research_slug,
            "display_title": release.display_title,
            "release_key": release.release_key,
            "documents": [
                {
                    "document_slug": item.spec.document_slug,
                    "document_role": item.spec.document_role,
                    "navigation_role": item.spec.navigation_role,
                    "sort_key": item.spec.sort_key,
                    "origin_uri": item.source_origin_uri,
                    "object_urn": f"qrh:object:{item.object_id}",
                    "content_sha256": item.projection.document_sha256,
                    "bytes": len(item.source_bytes),
                    "mapping_authority_urn": item.spec.mapping_authority_urn,
                    "mapping_note": item.spec.mapping_note,
                    "projection_validation_manifest_hash": item.validation_manifest_hash,
                    "rendered_object_urn": f"qrh:object:{item.rendered_object_id}",
                }
                for item in ordered
            ],
            "version_relations": [
                relation.model_dump(mode="json")
                for relation in sorted(
                    release.version_relations,
                    key=lambda relation: (
                        relation.document_slug,
                        relation.from_content_sha256,
                        relation.to_content_sha256,
                        relation.relation_kind,
                    ),
                )
            ],
            "summary_sha256": (
                sha256_hex(release.summary.encode("utf-8"))
                if release.summary is not None
                else None
            ),
            "summary_provenance_urn": release.summary_provenance_urn,
            "summary_artifact_urn": summary_artifact_urn,
        }
        artifact_manifest_hash = sha256_hex(
            canonical_json(manifest_payload).encode("utf-8")
        )
        source_snapshot_hash = sha256_hex(
            canonical_json(
                {
                    "schema_version": "archive-source-snapshot-set/v1",
                    "sources": [
                        {
                            "origin_uri": item.source_origin_uri,
                            "object_urn": f"qrh:object:{item.object_id}",
                            "content_sha256": item.projection.document_sha256,
                            "bytes": len(item.source_bytes),
                        }
                        for item in ordered
                    ],
                }
            ).encode("utf-8")
        )
        projection_revision = stable_sha256(
            "archive-projection-set/v1",
            *(item.validation_manifest_hash for item in ordered),
        )
        requirements_manifest_hash = stable_sha256(
            "archive-release-requirements/v1",
            "approved-source-identity",
            "exact-source-object",
            "safe-markdown-projection",
            "one-primary-document",
            "explicit-release-certificate",
        )
        return (
            ReleaseCandidateSpec(
                domain="archive",
                subject_urn=f"qrh:archive-research:{release.research_slug}",
                subject_version_urn=(
                    f"qrh:archive-release:{release.research_slug}:sha256:"
                    f"{artifact_manifest_hash}"
                ),
                artifact_manifest_hash=artifact_manifest_hash,
                source_snapshot_hash=source_snapshot_hash,
                projection_revision=projection_revision,
                requirements_manifest_hash=requirements_manifest_hash,
            ),
            manifest_payload,
        )

    def prepare_release_candidate(
        self, release: ArchiveReleaseInput
    ) -> ReleaseCandidateSpec:
        """冻结可供独立 gate 审阅的候选，不创建 research 或 active release。"""

        self.initialize()
        prepared = tuple(self._prepare_document(item) for item in release.documents)
        self._prepare_summary_artifact(release)
        candidate, _ = self._candidate_spec(release, prepared)
        return candidate

    def publish_release(self, release: ArchiveReleaseInput) -> PublishedArchiveRelease:
        """登记、投影并（若有证书）原子激活一次研究 release。

        只读 source/object/projection 在事务前完成；Archive DB 只在全部派生物已逐字节
        验证后写入。中途失败最多留下不可变 orphan，不会切换 active pointer。
        """

        self.initialize()
        prepared = tuple(self._prepare_document(item) for item in release.documents)
        self._prepare_summary_artifact(release)
        candidate_spec, _ = self._candidate_spec(release, prepared)
        certificate: ReleaseCertificate | None = None
        if release.activate:
            assert release.release_snapshot_urn is not None
            assert release.activation_decision_hash is not None
            certificate = ReleaseAuthority(self.settings).verify_snapshot(
                release.release_snapshot_urn,
                release.activation_decision_hash,
                candidate_spec,
            )
        with archive_connection(self.settings) as connection, immediate_transaction(connection):
            research_id = self._research(connection, release)
            version_rows = [
                self._document_version(connection, research_id, item) for item in prepared
            ]
            self._version_relations(connection, release, version_rows)
            document_manifest_hash = candidate_spec.artifact_manifest_hash
            release_row = connection.execute(
                """
                SELECT research_release_id,candidate_status FROM research_release
                WHERE research_id=? AND document_manifest_hash=?
                """,
                (research_id, document_manifest_hash),
            ).fetchone()
            created = release_row is None
            if release_row is None:
                research_release_id = new_public_id("rel")
                connection.execute(
                    """
                    INSERT INTO research_release(
                        research_release_id,research_id,document_manifest_hash,candidate_status,created_at
                    ) VALUES(?,?,?,'staging',?)
                    """,
                    (research_release_id, research_id, document_manifest_hash, utc_now()),
                )
                for item, row in zip(prepared, version_rows, strict=True):
                    connection.execute(
                        """
                        INSERT INTO research_release_item(
                            research_release_id,document_id,document_version_id,navigation_role,sort_key
                        ) VALUES(?,?,?,?,?)
                        """,
                        (
                            research_release_id,
                            row["document_id"],
                            row["document_version_id"],
                            item.spec.navigation_role,
                            item.spec.sort_key,
                        ),
                    )
                if release.summary is not None:
                    self._store_summary(connection, research_release_id, release)
            else:
                research_release_id = str(release_row["research_release_id"])
                self._verify_release_items(
                    connection, research_release_id, prepared, version_rows
                )
                if release.summary is not None:
                    self._store_summary(connection, research_release_id, release)

            self._candidate_identity(
                connection,
                research_id=research_id,
                research_release_id=research_release_id,
                release_key=release.release_key,
                candidate_spec=candidate_spec,
            )

            activation_id: str | None = None
            active_revision: int | None = None
            if release.activate:
                assert certificate is not None
                status = str(
                    connection.execute(
                        "SELECT candidate_status FROM research_release WHERE research_release_id=?",
                        (research_release_id,),
                    ).fetchone()[0]
                )
                if status == "staging":
                    for next_status in ("validated", "under_review", "releasable"):
                        connection.execute(
                            "UPDATE research_release SET candidate_status=? WHERE research_release_id=?",
                            (next_status, research_release_id),
                        )
                    status = "releasable"
                if status != "releasable":
                    raise ArchiveMappingConflict(
                        f"archive release cannot consume a certificate from status {status!r}"
                    )
                activation_id, active_revision = self._activate(
                    connection,
                    research_id=research_id,
                    research_release_id=research_release_id,
                    release_snapshot_urn=release.release_snapshot_urn,
                    decision_hash=release.activation_decision_hash,
                    documents=prepared,
                    versions=version_rows,
                    display_title=release.display_title,
                )
                self._record_authority_consumption(
                    connection,
                    activation_id=activation_id,
                    research_id=research_id,
                    research_release_id=research_release_id,
                    certificate=certificate,
                )
                from quant_hub.collaboration.service import ArchiveCollaboration

                ArchiveCollaboration(self.settings).recompute_after_release_activation(
                    connection, research_id
                )
            published = PublishedArchiveRelease(
                research_id=research_id,
                research_release_id=research_release_id,
                activation_id=activation_id,
                active_revision=active_revision,
                document_version_ids=tuple(str(row["document_version_id"]) for row in version_rows),
                document_manifest_hash=document_manifest_hash,
                candidate_spec=candidate_spec,
                created=created,
            )
        if release.activate:
            # File export is deliberately after the release transaction. A
            # failed file write leaves the committed update outbox pending and
            # therefore cannot roll back or partially expose the active pointer.
            from quant_hub.collaboration.service import ArchiveCollaboration

            ArchiveCollaboration(self.settings).export_research_update_history()
        return published

    @staticmethod
    def _research(connection: sqlite3.Connection, release: ArchiveReleaseInput) -> str:
        row = connection.execute(
            "SELECT research_id,display_title,lifecycle_status FROM research WHERE canonical_slug=?",
            (release.research_slug,),
        ).fetchone()
        if row is None:
            research_id = new_public_id("res")
            connection.execute(
                "INSERT INTO research(research_id,canonical_slug,display_title,lifecycle_status,created_at) VALUES(?,?,?,'active',?)",
                (research_id, release.research_slug, release.display_title, utc_now()),
            )
            return research_id
        if row["display_title"] != release.display_title or row["lifecycle_status"] != "active":
            raise ArchiveMappingConflict(
                "research slug already exists with a different title or lifecycle"
            )
        return str(row["research_id"])

    def _document_version(
        self,
        connection: sqlite3.Connection,
        research_id: str,
        prepared: PreparedArchiveDocument,
    ) -> dict[str, Any]:
        spec = prepared.spec
        document = connection.execute(
            "SELECT document_id,document_role FROM research_document WHERE research_id=? AND slug=?",
            (research_id, spec.document_slug),
        ).fetchone()
        if document is None:
            document_id = new_public_id("doc")
            connection.execute(
                "INSERT INTO research_document(document_id,research_id,document_role,slug,created_at) VALUES(?,?,?,?,?)",
                (document_id, research_id, spec.document_role, spec.document_slug, utc_now()),
            )
        else:
            if document["document_role"] != spec.document_role:
                raise ArchiveMappingConflict("document role conflicts with the approved mapping")
            document_id = str(document["document_id"])
        source_urn = f"qrh:source:{prepared.source_location_id}"
        evidence_json = canonical_json(
            {
                "schema_version": "archive-document-mapping/v1",
                "source_path": spec.source_path,
                "authority_urn": spec.mapping_authority_urn,
                "note": spec.mapping_note,
            }
        )
        origin = connection.execute(
            "SELECT mapping_status,mapping_evidence_json FROM research_document_origin WHERE document_id=? AND source_location_urn=?",
            (document_id, source_urn),
        ).fetchone()
        if origin is None:
            connection.execute(
                """
                INSERT INTO research_document_origin(
                    origin_id,document_id,source_location_urn,origin_kind,mapping_status,
                    mapping_evidence_json,first_seen_at
                ) VALUES(?,?,?,'archive_path','verified',?,?)
                """,
                (new_public_id("orgn"), document_id, source_urn, evidence_json, utc_now()),
            )
        elif (origin["mapping_status"], origin["mapping_evidence_json"]) != (
            "verified",
            evidence_json,
        ):
            raise ArchiveMappingConflict("source origin has conflicting mapping evidence")
        digest = prepared.projection.document_sha256
        version = connection.execute(
            """
            SELECT * FROM research_document_version
            WHERE document_id=? AND content_sha256=?
            """,
            (document_id, digest),
        ).fetchone()
        if version is None:
            version_created = True
            document_version_id = new_public_id("ver")
            connection.execute(
                """
                INSERT INTO research_document_version(
                    document_version_id,document_id,object_urn,content_sha256,bytes,encoding,
                    source_observed_at,created_at,discovery_status,parser_status
                ) VALUES(?,?,?,?,?, 'utf-8',?,?,'registered','succeeded')
                """,
                (
                    document_version_id,
                    document_id,
                    f"qrh:object:{prepared.object_id}",
                    digest,
                    len(prepared.source_bytes),
                    prepared.source_observed_at,
                    utc_now(),
                ),
            )
        else:
            version_created = False
            document_version_id = str(version["document_version_id"])
            expected = (
                f"qrh:object:{prepared.object_id}",
                len(prepared.source_bytes),
                "utf-8",
                "registered",
                "succeeded",
            )
            actual = (
                version["object_urn"], version["bytes"], version["encoding"],
                version["discovery_status"], version["parser_status"],
            )
            if actual != expected:
                raise ArchiveMappingConflict("document version identity or state conflicts")
        self._projection(connection, document_version_id, prepared)
        if version_created:
            payload = {
                "research_id": research_id,
                "document_id": document_id,
                "document_version_id": document_version_id,
                "document_slug": spec.document_slug,
                "source_location_urn": f"qrh:source:{prepared.source_location_id}",
                "source_origin_uri": prepared.source_origin_uri,
                "object_urn": f"qrh:object:{prepared.object_id}",
                "content_sha256": digest,
                "bytes": len(prepared.source_bytes),
                "parser_status": "succeeded",
            }
            payload_json = canonical_json(payload)
            connection.execute(
                """
                INSERT INTO outbox_event(
                    event_id,event_type,event_version,aggregate_urn,payload_json,
                    payload_hash,created_at,published_at,publish_attempt_count
                ) VALUES(?,'ArchiveDocumentVersionRegistered','1',?,?,?,?,NULL,0)
                """,
                (
                    new_public_id("evt"),
                    f"qrh:document:{document_id}",
                    payload_json,
                    stable_sha256("archive-outbox/v1", payload_json),
                    utc_now(),
                ),
            )
        return {
            "document_id": document_id,
            "document_version_id": document_version_id,
            "content_sha256": digest,
            "created": version_created,
        }

    @staticmethod
    def _version_relations(
        connection: sqlite3.Connection,
        release: ArchiveReleaseInput,
        current_versions: list[dict[str, str]],
    ) -> None:
        current_by_slug = {
            item.document_slug: row
            for item, row in zip(release.documents, current_versions, strict=True)
        }
        for relation in release.version_relations:
            current = current_by_slug[relation.document_slug]
            document_id = current["document_id"]
            from_row = connection.execute(
                """
                SELECT document_version_id FROM research_document_version
                WHERE document_id=? AND content_sha256=?
                """,
                (document_id, relation.from_content_sha256),
            ).fetchone()
            to_row = connection.execute(
                """
                SELECT document_version_id FROM research_document_version
                WHERE document_id=? AND content_sha256=?
                """,
                (document_id, relation.to_content_sha256),
            ).fetchone()
            if from_row is None or to_row is None:
                raise ArchiveMappingConflict(
                    "version relation references a version not registered for this document"
                )
            existing = connection.execute(
                """
                SELECT status,provenance_urn FROM document_version_relation
                WHERE from_document_version_id=? AND to_document_version_id=?
                  AND relation_kind=?
                """,
                (
                    from_row["document_version_id"], to_row["document_version_id"],
                    relation.relation_kind,
                ),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO document_version_relation(
                        relation_id,from_document_version_id,to_document_version_id,
                        relation_kind,status,provenance_urn,created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        new_public_id("vrel"), from_row["document_version_id"],
                        to_row["document_version_id"], relation.relation_kind,
                        relation.status, relation.provenance_urn, utc_now(),
                    ),
                )
            elif (existing["status"], existing["provenance_urn"]) != (
                relation.status,
                relation.provenance_urn,
            ):
                raise ArchiveMappingConflict("version relation provenance conflicts")

    @staticmethod
    def _projection(
        connection: sqlite3.Connection,
        document_version_id: str,
        prepared: PreparedArchiveDocument,
    ) -> None:
        projection = prepared.projection
        toc_json = canonical_json([_toc_row(entry) for entry in projection.toc])
        section_rows = [asdict(heading) for heading in projection.headings]
        section_json = canonical_json(section_rows)
        rows = connection.execute(
            """
            SELECT * FROM document_projection
            WHERE document_version_id=?
            """,
            (document_version_id,),
        ).fetchall()
        row = next(
            (
                candidate
                for candidate in rows
                if str(candidate["projector_version"]) == projection.projector_version
                and str(candidate["input_sha256"]) == projection.document_sha256
            ),
            None,
        )
        rendered_urn = f"qrh:object:{prepared.rendered_object_id}"

        # `outline_node` is deliberately the single current materialized outline for a
        # document version (its uniqueness key does not include projector_version), and
        # all read queries likewise expect exactly one ready document_projection row.
        # When the deterministic projector is upgraded, replace those derived rows in
        # this surrounding publication transaction.  Source/version/release history is
        # immutable; only the reproducible presentation projection is superseded.
        replacing_projection = row is None and bool(rows)
        if replacing_projection:
            preserved_search_revision = max(int(item["search_revision"]) for item in rows)
            connection.execute(
                "DELETE FROM outline_node WHERE document_version_id=?",
                (document_version_id,),
            )
            connection.execute(
                "DELETE FROM document_projection WHERE document_version_id=?",
                (document_version_id,),
            )
            rows = []

        if row is None:
            connection.execute(
                """
                INSERT INTO document_projection(
                    projection_id,document_version_id,projector_version,input_sha256,toc_json,
                    section_index_json,rendered_object_urn,search_revision,
                    validation_manifest_hash,status,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,'ready',?)
                """,
                (
                    new_public_id("prj"), document_version_id, projection.projector_version,
                    projection.document_sha256, toc_json, section_json, rendered_urn,
                    preserved_search_revision if replacing_projection else 0,
                    prepared.validation_manifest_hash, utc_now(),
                ),
            )
            for heading in projection.headings:
                parent_node = None
                if heading.parent_anchor_id is not None:
                    parent = connection.execute(
                        "SELECT node_id FROM outline_node WHERE document_version_id=? AND anchor_id=?",
                        (document_version_id, heading.parent_anchor_id),
                    ).fetchone()
                    if parent is None:
                        raise RuntimeError("heading parent was not projected before its child")
                    parent_node = str(parent["node_id"])
                connection.execute(
                    """
                    INSERT INTO outline_node(
                        node_id,document_version_id,parent_node_id,level,ordinal,title_text,
                        line_start,line_end,byte_start,byte_end,anchor_id
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        new_public_id("node"), document_version_id, parent_node,
                        heading.level, heading.ordinal, heading.title_text,
                        heading.line_start, heading.line_end, heading.byte_start,
                        heading.byte_end, heading.anchor_id,
                    ),
                )
        else:
            actual = (
                row["toc_json"], row["section_index_json"], row["rendered_object_urn"],
                row["validation_manifest_hash"], row["status"],
            )
            expected = (
                toc_json, section_json, rendered_urn,
                prepared.validation_manifest_hash, "ready",
            )
            if actual != expected:
                raise ArchiveMappingConflict("existing document projection conflicts")
            # Older builds could leave more than one projection row although every
            # reader treats this table as a one-row materialization.  Once the exact
            # deterministic row has been verified, remove only stale derived variants.
            connection.execute(
                "DELETE FROM document_projection WHERE document_version_id=? AND projection_id<>?",
                (document_version_id, row["projection_id"]),
            )
            count = connection.execute(
                "SELECT count(*) AS n FROM outline_node WHERE document_version_id=?",
                (document_version_id,),
            ).fetchone()["n"]
            if int(count) != len(projection.headings):
                raise ArchiveMappingConflict("existing outline is incomplete")

    @staticmethod
    def _store_summary(
        connection: sqlite3.Connection,
        release_id: str,
        release: ArchiveReleaseInput,
    ) -> None:
        assert release.summary is not None
        assert release.summary_provenance_urn is not None
        artifact = ArchiveCatalog._summary_artifact(release)
        assert artifact is not None
        artifact_bytes, artifact_urn = artifact
        payload = artifact_bytes.decode("utf-8")
        artifact_id = artifact_urn
        row = connection.execute(
            """
            SELECT payload_json FROM derived_research_metadata
            WHERE research_release_id=? AND derivation_type='summary'
              AND derivation_version='1' AND artifact_id=?
            """,
            (release_id, artifact_id),
        ).fetchone()
        if row is None:
            connection.execute(
                """
                INSERT INTO derived_research_metadata(
                    metadata_id,document_version_id,research_release_id,derivation_type,
                    derivation_version,payload_json,artifact_id,status,created_at
                ) VALUES(?,NULL,?,'summary','1',?,?,'validated',?)
                """,
                (new_public_id("meta"), release_id, payload, artifact_id, utc_now()),
            )
        elif row["payload_json"] != payload:
            raise ArchiveMappingConflict("summary artifact identity conflicts")

    @staticmethod
    def _verify_release_items(
        connection: sqlite3.Connection,
        release_id: str,
        prepared: tuple[PreparedArchiveDocument, ...],
        versions: list[dict[str, str]],
    ) -> None:
        rows = connection.execute(
            """
            SELECT document_id,document_version_id,navigation_role,sort_key
            FROM research_release_item WHERE research_release_id=?
            ORDER BY sort_key,document_id
            """,
            (release_id,),
        ).fetchall()
        expected = sorted(
            (
                row["document_id"], row["document_version_id"],
                item.spec.navigation_role, item.spec.sort_key,
            )
            for item, row in zip(prepared, versions, strict=True)
        )
        actual = sorted(
            (str(row["document_id"]), str(row["document_version_id"]), str(row["navigation_role"]), int(row["sort_key"]))
            for row in rows
        )
        if actual != expected:
            raise ArchiveMappingConflict("existing release items conflict with manifest")

    @staticmethod
    def _candidate_identity(
        connection: sqlite3.Connection,
        *,
        research_id: str,
        research_release_id: str,
        release_key: str,
        candidate_spec: ReleaseCandidateSpec,
    ) -> None:
        row = connection.execute(
            """
            SELECT * FROM research_release_candidate_identity
            WHERE research_release_id=?
            """,
            (research_release_id,),
        ).fetchone()
        expected = (
            research_id,
            release_key,
            candidate_spec.subject_urn,
            candidate_spec.subject_version_urn,
            candidate_spec.artifact_manifest_hash,
            candidate_spec.source_snapshot_hash,
            candidate_spec.requirements_manifest_hash,
            candidate_spec.projection_revision,
        )
        if row is None:
            connection.execute(
                """
                INSERT INTO research_release_candidate_identity(
                    research_release_id,research_id,release_key,subject_urn,
                    subject_version_urn,artifact_manifest_hash,source_snapshot_hash,
                    requirements_manifest_hash,projection_revision,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (research_release_id, *expected, utc_now()),
            )
            return
        actual = (
            str(row["research_id"]),
            str(row["release_key"]),
            str(row["subject_urn"]),
            str(row["subject_version_urn"]),
            str(row["artifact_manifest_hash"]),
            str(row["source_snapshot_hash"]),
            str(row["requirements_manifest_hash"]),
            str(row["projection_revision"]),
        )
        if actual != expected:
            raise ArchiveMappingConflict("archive release candidate identity conflicts")

    @staticmethod
    def _record_authority_consumption(
        connection: sqlite3.Connection,
        *,
        activation_id: str,
        research_id: str,
        research_release_id: str,
        certificate: ReleaseCertificate,
    ) -> None:
        row = connection.execute(
            """
            SELECT platform_candidate_id,release_snapshot_urn,decision_hash
            FROM research_release_authority_consumption WHERE activation_id=?
            """,
            (activation_id,),
        ).fetchone()
        expected = (
            certificate.candidate_id,
            certificate.snapshot_urn,
            certificate.decision_hash,
        )
        if row is None:
            connection.execute(
                """
                INSERT INTO research_release_authority_consumption(
                    activation_id,research_id,research_release_id,platform_candidate_id,
                    release_snapshot_urn,decision_hash,consumed_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    activation_id,
                    research_id,
                    research_release_id,
                    certificate.candidate_id,
                    certificate.snapshot_urn,
                    certificate.decision_hash,
                    utc_now(),
                ),
            )
            return
        actual = (
            str(row["platform_candidate_id"]),
            str(row["release_snapshot_urn"]),
            str(row["decision_hash"]),
        )
        if actual != expected:
            raise ArchiveMappingConflict("release authority consumption conflicts")

    def _activate(
        self,
        connection: sqlite3.Connection,
        *,
        research_id: str,
        research_release_id: str,
        release_snapshot_urn: str,
        decision_hash: str,
        documents: tuple[PreparedArchiveDocument, ...],
        versions: list[dict[str, str]],
        display_title: str,
    ) -> tuple[str, int]:
        from quant_hub.collaboration.service import ArchiveCollaboration

        existing = connection.execute(
            "SELECT * FROM research_release_activation WHERE research_id=? AND release_snapshot_urn=?",
            (research_id, release_snapshot_urn),
        ).fetchone()
        active = connection.execute(
            "SELECT * FROM active_research_release WHERE research_id=?",
            (research_id,),
        ).fetchone()
        if existing is not None:
            if (
                existing["research_release_id"] != research_release_id
                or existing["decision_hash"] != decision_hash
            ):
                raise ArchiveMappingConflict("release snapshot URN is already bound differently")
            activation_id = str(existing["activation_id"])
            if active is None or active["activation_id"] != activation_id:
                raise ArchiveMappingConflict(
                    "an old activation certificate cannot silently replace the current release"
                )
            revision = int(active["revision"])
            ArchiveCollaboration.record_research_update_after_activation(
                connection,
                research_id=research_id,
                research_release_id=research_release_id,
                activation_id=activation_id,
                release_revision=revision,
            )
            return activation_id, revision
        activation_id = new_public_id("actv")
        now = utc_now()
        predecessor = str(active["activation_id"]) if active else None
        connection.execute(
            """
            INSERT INTO research_release_activation(
                activation_id,research_id,research_release_id,release_snapshot_urn,
                decision_hash,activated_at,supersedes_activation_id
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                activation_id, research_id, research_release_id, release_snapshot_urn,
                decision_hash, now, predecessor,
            ),
        )
        if active is None:
            revision = 1
            connection.execute(
                """
                INSERT INTO active_research_release(
                    research_id,activation_id,research_release_id,release_snapshot_urn,revision
                ) VALUES(?,?,?,?,1)
                """,
                (research_id, activation_id, research_release_id, release_snapshot_urn),
            )
        else:
            revision = int(active["revision"]) + 1
            connection.execute(
                """
                UPDATE active_research_release
                SET activation_id=?,research_release_id=?,release_snapshot_urn=?,revision=?
                WHERE research_id=?
                """,
                (activation_id, research_release_id, release_snapshot_urn, revision, research_id),
            )
        connection.execute(
            "UPDATE derived_research_metadata SET status='released' WHERE research_release_id=? AND derivation_type='summary' AND status='validated'",
            (research_release_id,),
        )
        connection.execute("DELETE FROM document_search_projection WHERE research_id=?", (research_id,))
        for item, row in zip(documents, versions, strict=True):
            connection.execute(
                """
                INSERT INTO document_search_projection(
                    research_id,document_version_id,title_text,search_text,
                    projector_version,search_revision,updated_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    research_id,
                    row["document_version_id"],
                    f"{display_title} · {item.spec.document_slug}",
                    item.projection.plain_text,
                    item.projection.projector_version,
                    revision,
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE document_projection SET search_revision=?
                WHERE document_version_id=? AND projector_version=? AND input_sha256=?
                """,
                (
                    revision, row["document_version_id"], item.projection.projector_version,
                    item.projection.document_sha256,
                ),
            )
        payload = {
            "research_id": research_id,
            "research_release_id": research_release_id,
            "activation_id": activation_id,
            "release_snapshot_urn": release_snapshot_urn,
            "decision_hash": decision_hash,
            "revision": revision,
        }
        payload_json = canonical_json(payload)
        connection.execute(
            """
            INSERT INTO outbox_event(
                event_id,event_type,event_version,aggregate_urn,payload_json,payload_hash,
                created_at,published_at,publish_attempt_count
            ) VALUES(?,'ArchiveResearchReleaseActivated','1',?,?,?,?,NULL,0)
            """,
            (
                new_public_id("evt"), f"qrh:research:{research_id}", payload_json,
                stable_sha256("archive-outbox/v1", payload_json), now,
            ),
        )
        ArchiveCollaboration.record_research_update_after_activation(
            connection,
            research_id=research_id,
            research_release_id=research_release_id,
            activation_id=activation_id,
            release_revision=revision,
        )
        self._archive_link_index_cache = None
        return activation_id, revision

    @staticmethod
    def _archive_path_from_origin(origin_uri: str) -> str:
        split = urlsplit(origin_uri)
        if split.scheme != "archive" or split.netloc or split.query or split.fragment:
            raise ArchiveMappingConflict(
                "active Archive document has a non-canonical source origin"
            )
        relative = unquote(split.path).lstrip("/")
        return validate_archive_relative_path(relative)

    def _active_source_paths(
        self,
        rows: list[sqlite3.Row],
        *,
        research_slug: str | None = None,
    ) -> dict[str, str]:
        """以 platform source_location + active object exact match恢复来源路径。

        同一 logical document 可拥有多个历史 origin；只有同时出现在已核验映射中
        且 object_id 与当前 active document version 一致的来源才可用于展示链接。
        """

        source_ids: set[str] = set()
        row_origins: dict[str, tuple[str, ...]] = {}
        for row in rows:
            version_id = str(row["document_version_id"])
            raw = json.loads(str(row["origin_urns_json"]))
            if not isinstance(raw, list):
                raise ArchiveMappingConflict("document origin set is not a JSON array")
            ids: list[str] = []
            for urn in raw:
                if not isinstance(urn, str) or not urn.startswith("qrh:source:src_"):
                    raise ArchiveMappingConflict("document source URN is not canonical")
                source_id = urn.removeprefix("qrh:source:")
                ids.append(source_id)
                source_ids.add(source_id)
            row_origins[version_id] = tuple(ids)
        if not source_ids:
            return {}
        placeholders = ",".join("?" for _ in source_ids)
        platform = connect_database(self.settings.database_path)
        try:
            source_rows = platform.execute(
                f"""
                SELECT source_location_id,origin_uri,object_id
                FROM source_location
                WHERE source_location_id IN ({placeholders})
                """,
                tuple(sorted(source_ids)),
            ).fetchall()
        finally:
            platform.close()
        by_id = {str(row["source_location_id"]): row for row in source_rows}
        paths: dict[str, str] = {}
        for row in rows:
            version_id = str(row["document_version_id"])
            object_id = _object_id_from_urn(str(row["object_urn"]))
            matches = {
                self._archive_path_from_origin(str(by_id[source_id]["origin_uri"]))
                for source_id in row_origins[version_id]
                if source_id in by_id and str(by_id[source_id]["object_id"]) == object_id
            }
            row_slug = research_slug
            if row_slug is None and "canonical_slug" in row.keys():
                row_slug = str(row["canonical_slug"])
            if len(matches) > 1 and row_slug:
                presentation = self.presentation.research.get(row_slug)
                current_paths = (
                    set(presentation["document_titles"])
                    if presentation is not None
                    else set()
                )
                reviewed_current_matches = matches & current_paths
                if len(reviewed_current_matches) == 1:
                    matches = reviewed_current_matches
            if len(matches) != 1:
                raise ArchiveMappingConflict(
                    "active document version does not have one exact verified source path"
                )
            paths[version_id] = matches.pop()
        return paths

    def _verified_origin_alias_paths(
        self, rows: list[sqlite3.Row]
    ) -> dict[str, tuple[str, ...]]:
        """返回审核映射到 logical document 的全部历史来源精确路径。"""

        source_ids: set[str] = set()
        by_version: dict[str, tuple[str, ...]] = {}
        for row in rows:
            values = json.loads(str(row["origin_urns_json"]))
            ids = tuple(
                str(value).removeprefix("qrh:source:")
                for value in values
                if isinstance(value, str) and value.startswith("qrh:source:src_")
            )
            by_version[str(row["document_version_id"])] = ids
            source_ids.update(ids)
        if not source_ids:
            return {}
        placeholders = ",".join("?" for _ in source_ids)
        platform = connect_database(self.settings.database_path)
        try:
            source_rows = platform.execute(
                f"SELECT source_location_id,origin_uri FROM source_location "
                f"WHERE source_location_id IN ({placeholders})",
                tuple(sorted(source_ids)),
            ).fetchall()
        finally:
            platform.close()
        paths = {
            str(row["source_location_id"]): self._archive_path_from_origin(
                str(row["origin_uri"])
            )
            for row in source_rows
        }
        return {
            version_id: tuple(
                sorted({paths[source_id] for source_id in ids if source_id in paths})
            )
            for version_id, ids in by_version.items()
        }

    def _content_alias_paths(
        self, rows: list[sqlite3.Row]
    ) -> dict[str, tuple[str, ...]]:
        """返回与 active bytes 完全相同的 Archive 来源路径，不做名称推断。"""

        object_ids = {
            _object_id_from_urn(str(row["object_urn"])) for row in rows
        }
        if not object_ids:
            return {}
        placeholders = ",".join("?" for _ in object_ids)
        platform = connect_database(self.settings.database_path)
        try:
            source_rows = platform.execute(
                f"""
                SELECT object_id,origin_uri FROM source_location
                WHERE namespace='archive' AND object_id IN ({placeholders})
                """,
                tuple(sorted(object_ids)),
            ).fetchall()
        finally:
            platform.close()
        by_object: dict[str, set[str]] = {}
        for row in source_rows:
            by_object.setdefault(str(row["object_id"]), set()).add(
                self._archive_path_from_origin(str(row["origin_uri"]))
            )
        return {
            str(row["document_version_id"]): tuple(
                sorted(by_object.get(_object_id_from_urn(str(row["object_urn"])), set()))
            )
            for row in rows
        }

    @staticmethod
    def _origin_set_sql() -> str:
        return """
            COALESCE((
                SELECT json_group_array(origin.source_location_urn)
                FROM research_document_origin AS origin
                WHERE origin.document_id=document.document_id
                  AND origin.mapping_status='verified'
            ), '[]') AS origin_urns_json
        """

    @staticmethod
    def _fragment_key(value: str) -> str:
        folded = value.casefold().strip().replace(" ", "-")
        return re.sub(r"[^\w\-\u4e00-\u9fff]+", "", folded)

    @staticmethod
    def _chapter_toc(
        sections: list[dict[str, Any]], chapter: ArchiveChapter
    ) -> list[dict[str, Any]]:
        """Build a light local tree while retaining full-document anchor IDs."""

        selected = [
            section
            for section in sections
            if chapter.absolute_start
            <= int(section["byte_start"])
            < chapter.absolute_end
            and not str(section["title_text"]).startswith(
                "Pipeline 概览图（按三步 pipeline + 跨步骤重组）"
            )
        ]
        roots: list[dict[str, Any]] = []
        stack: list[dict[str, Any]] = []
        for section in selected:
            node = {
                "anchor_id": str(section["anchor_id"]),
                "title_text": str(section["title_text"]),
                "level": int(section["level"]),
                "children": [],
            }
            while stack and int(stack[-1]["level"]) >= node["level"]:
                stack.pop()
            if stack:
                stack[-1]["children"].append(node)
            else:
                roots.append(node)
            stack.append(node)
        return roots

    def _chapter_rows(
        self,
        *,
        research_id: str,
        research_slug: str,
        release_key: str,
        source_path: str,
        source_sha256: str,
        sections: list[dict[str, Any]],
        document_id: str,
    ) -> list[dict[str, Any]]:
        manifest = self.chapter_manifests.manifest(research_slug)
        if manifest is None:
            return []
        bound_release = str(
            manifest["archive_release_binding"]["archive_release_key"]
        )
        # Historical releases remain readable through their immutable old
        # projection; a chapter manifest may only attach to the exact release
        # key that it reviewed.
        if bound_release != release_key:
            return []
        chapters = self.chapter_manifests.chapters(
            research_slug, source_path, source_sha256
        )
        rows: list[dict[str, Any]] = []
        for chapter in chapters:
            url = (
                f"/research/{research_id}/documents/{document_id}/chapters/"
                f"{chapter.route_slug}"
            )
            rows.append(
                {
                    "chapter_key": chapter.chapter_key,
                    "chapter_revision_id": chapter.chapter_revision_id,
                    "route_slug": chapter.route_slug,
                    "display_title": chapter.display_title,
                    "group": chapter.group,
                    "ordinal": chapter.ordinal,
                    "absolute_start": chapter.absolute_start,
                    "absolute_end": chapter.absolute_end,
                    "bytes": chapter.bytes,
                    "source_slice_sha256": chapter.source_slice_sha256,
                    "heading_anchor_ids": chapter.heading_anchor_ids,
                    "page_url": url,
                    "toc": self._chapter_toc(sections, chapter),
                }
            )
        return rows

    @staticmethod
    def _group_chapters(chapters: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: list[dict[str, Any]] = []
        by_title: dict[str, dict[str, Any]] = {}
        for chapter in chapters:
            title = str(chapter["group"])
            group = by_title.get(title)
            if group is None:
                group = {"title": title, "chapters": []}
                by_title[title] = group
                groups.append(group)
            group["chapters"].append(chapter)
        return groups

    def archive_link_index(self) -> dict[str, dict[str, Any]]:
        """构建 active/public source path 到页面精确位置的展示目录。"""

        if self._archive_link_index_cache is not None:
            return self._archive_link_index_cache

        with archive_connection(self.settings) as connection:
            rows = connection.execute(
                f"""
                SELECT research.canonical_slug,research.research_id,
                       research.display_title AS research_source_title,
                       document.document_id,document.slug,
                       version.document_version_id,version.object_urn,
                       version.content_sha256,release.release_key,
                       projection.section_index_json,
                       {self._origin_set_sql()}
                FROM active_research_release AS active
                JOIN research ON research.research_id=active.research_id
                JOIN research_release_item AS item
                  ON item.research_release_id=active.research_release_id
                JOIN research_release_candidate_identity AS release
                  ON release.research_release_id=active.research_release_id
                JOIN research_document AS document ON document.document_id=item.document_id
                JOIN research_document_version AS version
                  ON version.document_version_id=item.document_version_id
                JOIN document_projection AS projection
                  ON projection.document_version_id=version.document_version_id
                 AND projection.status='ready'
                WHERE research.lifecycle_status='active'
                ORDER BY research.canonical_slug,item.sort_key,document.document_id
                """
            ).fetchall()
        material = list(rows)
        source_paths = self._active_source_paths(material)
        origin_aliases = self._verified_origin_alias_paths(material)
        content_aliases = self._content_alias_paths(material)
        index: dict[str, dict[str, Any]] = {}
        for row in material:
            research_slug = str(row["canonical_slug"])
            if not self.presentation.is_public_research(research_slug):
                continue
            source_path = source_paths[str(row["document_version_id"])]
            sections = json.loads(str(row["section_index_json"]))
            first_heading = (
                str(sections[0]["title_text"])
                if isinstance(sections, list) and sections
                else None
            )
            target = {
                "research_id": str(row["research_id"]),
                "research_slug": research_slug,
                "research_title": self.presentation.research_title(
                    research_slug, str(row["research_source_title"])
                ),
                "document_id": str(row["document_id"]),
                "source_path": source_path,
                "title": self.presentation.document_title(
                    research_slug,
                    source_path,
                    first_heading,
                    str(row["slug"]),
                ),
                "sections": sections,
            }
            target["chapters"] = self._chapter_rows(
                research_id=str(row["research_id"]),
                research_slug=research_slug,
                release_key=str(row["release_key"]),
                source_path=source_path,
                source_sha256=str(row["content_sha256"]),
                sections=sections,
                document_id=str(row["document_id"]),
            )
            aliases = {
                source_path,
                *origin_aliases.get(str(row["document_version_id"]), ()),
                *content_aliases.get(str(row["document_version_id"]), ()),
            }
            for alias in aliases:
                existing = index.get(alias)
                if existing is not None and (
                    existing["research_id"], existing["document_id"]
                ) != (target["research_id"], target["document_id"]):
                    raise ArchiveMappingConflict(
                        f"exact source alias maps to two active documents: {alias}"
                    )
                index[alias] = target

        # 历史正文中仍保留少量旧文件名。只有展示 manifest 明确记录、且目标
        # 确实处于当前 public release 的精确改名才可成为别名；禁止按 basename
        # 或相似度猜测，以免把研究关系错误地指向同名文档。
        for alias_path, alias_spec in self.presentation.internal_link_aliases.items():
            target_path = alias_spec["target_path"]
            target = index.get(target_path)
            if target is None:
                # 增量/局部 release 可能尚未包含该目标。此时不安装别名；若
                # 正文实际引用它，resolve_archive_link 会按 unresolved 明示，
                # 不能因另一专题未发布而让整个当前页面失效。
                continue
            existing = index.get(alias_path)
            if existing is not None and (
                existing["research_id"], existing["document_id"]
            ) != (target["research_id"], target["document_id"]):
                raise ArchiveMappingConflict(
                    f"curated source alias conflicts with an active document: {alias_path}"
                )
            index[alias_path] = target
        self._archive_link_index_cache = index
        return index

    def _resolve_archive_index_target(
        self,
        target_path: str,
        fragment: str | None,
        *,
        index: dict[str, dict[str, Any]],
        title_override: str | None = None,
        missing_reason: str | None = None,
    ) -> InternalArchiveLink:
        target = index.get(target_path)
        if target is None:
            basename = target_path.rsplit("/", 1)[-1]
            stem = re.sub(r"\.(?:md|markdown)$", "", basename, flags=re.IGNORECASE)
            target_label = title_override or self.presentation.heading_title(
                re.sub(r"[_-]+", " ", stem).strip()
            )
            return InternalArchiveLink(
                state="unresolved",
                title=f"未解析目标：{target_label}",
                url="#unresolved-archive-link",
                source_path=target_path,
                reason=missing_reason
                or "目标文档未进入当前公开 release，或来源路径与审核映射不一致。",
            )
        display_title = title_override or str(target["title"])
        anchor: str | None = None
        if fragment is not None:
            fragment_key = self._fragment_key(fragment)
            matches = [
                section
                for section in target["sections"]
                if fragment == str(section.get("anchor_id", ""))
                or fragment == str(section.get("title_text", ""))
                or fragment_key == self._fragment_key(str(section.get("title_text", "")))
            ]
            if len(matches) != 1:
                return InternalArchiveLink(
                    state="unresolved",
                    title=f"未解析章节：{display_title} / {fragment}",
                    url="#unresolved-archive-link",
                    source_path=target_path,
                    reason="目标文档存在，但 fragment 不能唯一匹配当前稳定章节锚点。",
                )
            anchor = str(matches[0]["anchor_id"])
        chapters = list(target.get("chapters") or [])
        selected_chapter: dict[str, Any] | None = chapters[0] if chapters else None
        if anchor is not None and chapters:
            selected_chapter = next(
                (
                    chapter
                    for chapter in chapters
                    if anchor in chapter["heading_anchor_ids"]
                ),
                None,
            )
            if selected_chapter is None:
                return InternalArchiveLink(
                    state="unresolved",
                    title=f"章节索引未覆盖：{display_title} / {fragment}",
                    url="#unresolved-archive-link",
                    source_path=target_path,
                    reason="目标 heading 存在，但未被当前 release 的章节 manifest 覆盖。",
                )
        if selected_chapter is not None:
            url = str(selected_chapter["page_url"])
        else:
            url = (
                f"/research/{target['research_id']}/documents/{target['document_id']}"
            )
        if anchor is not None:
            url = f"{url}#{anchor}"
        return InternalArchiveLink(
            state="resolved",
            title=display_title,
            url=url,
            source_path=target_path,
        )

    def resolve_archive_link(
        self,
        current_source_path: str,
        reference: str,
        *,
        index: dict[str, dict[str, Any]],
    ) -> InternalArchiveLink:
        contextual = self.presentation.contextual_internal_link(
            current_source_path, reference
        )
        if contextual is not None:
            if contextual["state"] == "provenance":
                return InternalArchiveLink(
                    state="provenance",
                    title=str(contextual["title"]),
                    url="",
                    source_path=None,
                    reason=str(contextual["reason"]),
                )
            assert contextual["target_path"] is not None
            return self._resolve_archive_index_target(
                str(contextual["target_path"]),
                contextual["fragment"],
                index=index,
                title_override=str(contextual["title"]),
                missing_reason=str(contextual["reason"]),
            )
        if self.presentation.is_historical_provenance_reference(reference):
            return InternalArchiveLink(
                state="provenance",
                title=self.presentation.historical_provenance_label,
                url="",
                source_path=None,
                reason="旧源稿身份仅用于来源说明；相关内容已由当前专题承载。",
            )
        normalized = self.presentation.normalize_relative_archive_reference(
            current_source_path, reference
        )
        if normalized is None:
            return InternalArchiveLink(
                state="external",
                title=reference,
                url=reference,
                source_path=None,
            )
        target_path, fragment, kind = normalized
        if kind == "directory":
            directory = self.presentation.directory_internal_link(target_path)
            if directory is None:
                target_label = self.presentation.heading_title(
                    re.sub(r"[_-]+", " ", target_path.rsplit("/", 1)[-1]).strip()
                )
                return InternalArchiveLink(
                    state="unresolved",
                    title=f"未解析目录：{target_label}",
                    url="#unresolved-archive-link",
                    source_path=target_path,
                    reason="目录目标尚未建立经审核的公开 landing，不保留浏览器相对路径。",
                )
            return self._resolve_archive_index_target(
                str(directory["target_path"]),
                directory["fragment"],
                index=index,
                title_override=str(directory["title"]),
                missing_reason=str(directory["reason"]),
            )
        if kind == "asset":
            asset = self.presentation.internal_asset_for_path(target_path)
            if asset is None:
                target_label = self.presentation.internal_link_label(target_path)
                return InternalArchiveLink(
                    state="unresolved",
                    title=f"未解析资源：{target_label}",
                    url="#unresolved-archive-link",
                    source_path=target_path,
                    reason="非 Markdown 来源尚未进入受控资源清单，不保留浏览器相对路径。",
                )
            return InternalArchiveLink(
                state="resolved",
                title=str(asset["title"]),
                url=f"/api/v1/archive/assets/{asset['asset_id']}",
                source_path=target_path,
            )
        retired = self.presentation.retired_internal_link(target_path)
        if retired is not None:
            if retired["state"] == "label":
                return InternalArchiveLink(
                    state="label",
                    title=str(retired["title"]),
                    url="",
                    source_path=target_path,
                    reason=str(retired["reason"]),
                )
            assert retired["target_path"] is not None
            return self._resolve_archive_index_target(
                str(retired["target_path"]),
                (
                    str(retired["fragment"])
                    if retired["fragment"] is not None
                    else fragment
                ),
                index=index,
                title_override=str(retired["title"]),
                missing_reason=str(retired["reason"]),
            )
        return self._resolve_archive_index_target(
            target_path,
            fragment,
            index=index,
        )

    def list_research(self) -> list[dict[str, Any]]:
        with archive_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT research.research_id,research.canonical_slug,research.display_title,
                       active.research_release_id,status.work_status,status.release_status,
                       status.evidence_status,status.updated_at
                FROM research
                JOIN active_research_release AS active USING(research_id)
                LEFT JOIN research_status_projection AS status USING(research_id)
                WHERE research.lifecycle_status='active'
                ORDER BY research.display_title,research.research_id
                """
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            slug = str(item["canonical_slug"])
            if not self.presentation.is_public_research(slug):
                continue
            source_title = str(item["display_title"])
            item["source_display_title"] = source_title
            item["display_title"] = self.presentation.research_title(
                slug, source_title
            )
            item["presentation_summary"] = self.presentation.research_summary(slug)
            results.append(item)
        # 研究目录表达量化研究本身的业务序列；更新时间只用于首页更新流，
        # 不能让目录在每次发布后发生位置漂移。
        business_order = {
            "q1-product-factor-evaluation": 10,
            "q2-low-snr-neural-selection-factory": 20,
            "q3-training-method-reliability": 30,
            "q4-operations-post-deployment-monitoring": 40,
            "q5-factor-history-sequence-compression": 50,
            "poff-cross-cutting-diagnostics": 60,
            "archive-experiments-e1-e8": 70,
            "archive-governance-and-navigation": 80,
            "archive-reorganization-records": 90,
            "legacy-low-snr-research-source": 100,
        }
        results.sort(
            key=lambda item: (
                business_order.get(str(item["canonical_slug"]), 1_000),
                str(item["display_title"]),
                str(item["research_id"]),
            )
        )
        return results

    def research_page(
        self, research_id: str, *, include_rendered: bool = True
    ) -> dict[str, Any]:
        with archive_connection(self.settings) as connection:
            research = connection.execute(
                """
                SELECT research.*,active.research_release_id,active.revision,
                       release.release_key,
                       status.work_status,status.release_status,status.evidence_status
                FROM research
                JOIN active_research_release AS active USING(research_id)
                JOIN research_release_candidate_identity AS release
                  ON release.research_release_id=active.research_release_id
                LEFT JOIN research_status_projection AS status USING(research_id)
                WHERE research.research_id=?
                """,
                (research_id,),
            ).fetchone()
            if research is None:
                raise ArchiveNotFound(f"active research not found: {research_id}")
            if not self.presentation.is_public_research(
                str(research["canonical_slug"])
            ):
                raise ArchiveNotFound(f"research is not in public presentation: {research_id}")
            documents = connection.execute(
                f"""
                SELECT item.navigation_role,item.sort_key,document.document_id,
                       document.slug,document.document_role,version.document_version_id,
                       version.object_urn,version.content_sha256,version.bytes,
                       projection.toc_json,projection.section_index_json,
                       projection.rendered_object_urn,
                       {self._origin_set_sql()}
                FROM research_release_item AS item
                JOIN research_document AS document ON document.document_id=item.document_id
                JOIN research_document_version AS version
                  ON version.document_version_id=item.document_version_id
                JOIN document_projection AS projection
                  ON projection.document_version_id=version.document_version_id
                 AND projection.status='ready'
                WHERE item.research_release_id=?
                ORDER BY item.sort_key,document.document_id
                """,
                (research["research_release_id"],),
            ).fetchall()
        material = list(documents)
        research_slug = str(research["canonical_slug"])
        source_paths = self._active_source_paths(
            material, research_slug=research_slug
        )
        chapter_manifest = self.chapter_manifests.manifest(research_slug)
        chapter_manifest_enabled = bool(
            chapter_manifest is not None
            and str(
                chapter_manifest["archive_release_binding"]["archive_release_key"]
            )
            == str(research["release_key"])
        )
        page_documents: list[dict[str, Any]] = []
        for row in material:
            rendered = ""
            if include_rendered:
                rendered_urn = str(row["rendered_object_urn"])
                rendered = self.object_store.read_bytes(
                    _object_id_from_urn(rendered_urn)
                ).decode("utf-8")
            source_path = source_paths[str(row["document_version_id"])]
            sections = json.loads(str(row["section_index_json"]))
            first_heading = (
                str(sections[0]["title_text"])
                if isinstance(sections, list) and sections
                else None
            )

            def present_toc(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
                return [
                    {
                        **node,
                        "title_text": self.presentation.heading_title(
                            str(node["title_text"]), source_path
                        ),
                        "children": present_toc(list(node.get("children", []))),
                    }
                    for node in nodes
                ]

            presented_sections = [
                {
                    **section,
                    "title_text": self.presentation.heading_title(
                        str(section["title_text"]), source_path
                    ),
                }
                for section in sections
            ]
            manifest_document = (
                self.chapter_manifests.document(
                    research_slug, source_path, str(row["content_sha256"])
                )
                if chapter_manifest_enabled
                else None
            )
            document_row: dict[str, Any] = {
                    "document_id": str(row["document_id"]),
                    "document_version_id": str(row["document_version_id"]),
                    "slug": str(row["slug"]),
                    "document_role": str(row["document_role"]),
                    "navigation_role": str(row["navigation_role"]),
                    "content_sha256": str(row["content_sha256"]),
                    "bytes": int(row["bytes"]),
                    "source_path": source_path,
                    "display_title": (
                        str(manifest_document["display_title"])
                        if manifest_document is not None
                        else self.presentation.document_title(
                            research_slug,
                            source_path,
                            first_heading,
                            str(row["slug"]),
                        )
                    ),
                    "document_key": (
                        str(manifest_document["document_key"])
                        if manifest_document is not None
                        else str(row["slug"])
                    ),
                    "relationship": (
                        str(manifest_document["relationship"])
                        if manifest_document is not None
                        else None
                    ),
                    "page_url": (
                        f"/research/{research['research_id']}/documents/"
                        f"{row['document_id']}"
                    ),
                    "source_url": f"/api/v1/research/{research_id}/documents/{row['document_id']}/source",
                    "toc": present_toc(json.loads(str(row["toc_json"]))),
                    "sections": presented_sections,
                    "rendered_html": rendered,
                }
            chapter_rows = self._chapter_rows(
                research_id=str(research["research_id"]),
                research_slug=research_slug,
                release_key=str(research["release_key"]),
                source_path=source_path,
                source_sha256=str(row["content_sha256"]),
                sections=presented_sections,
                document_id=str(row["document_id"]),
            )
            document_row["chapters"] = chapter_rows
            document_row["chapter_groups"] = self._group_chapters(chapter_rows)
            document_row["is_chaptered"] = bool(chapter_rows)
            if chapter_rows:
                document_row["page_url"] = str(chapter_rows[0]["page_url"])
                # A chaptered release must never carry its persisted full HTML
                # into a request response, even if include_rendered was asked.
                document_row["rendered_html"] = ""
            page_documents.append(document_row)
        manifest = chapter_manifest
        if chapter_manifest_enabled and manifest is not None:
            expected = {
                (str(item["source_path"]), str(item["source_sha256"]))
                for item in manifest["documents"]
            }
            actual = {
                (str(item["source_path"]), str(item["content_sha256"]))
                for item in page_documents
            }
            if actual != expected or any(
                not item["chapters"] for item in page_documents
            ):
                raise ArchiveChapterManifestError(
                    "active release does not exactly match its sealed chapter manifest"
                )
        source_title = str(research["display_title"])
        entry_paths = self.presentation.research_entry_paths(research_slug)
        documents_by_path = {
            str(document["source_path"]): document for document in page_documents
        }
        documents_by_key = {
            str(document["document_key"]): document for document in page_documents
        }
        chapter_pages_by_revision = {
            str(chapter["chapter_revision_id"]): chapter
            for document in page_documents
            for chapter in document["chapters"]
        }
        pipeline_nodes: dict[str, dict[str, Any]] = {}
        if chapter_manifest_enabled and manifest is not None:
            for edge in manifest.get("pipeline_node_edges", []):
                target = chapter_pages_by_revision.get(
                    str(edge["target_chapter_revision_id"])
                )
                if target is None:
                    raise ArchiveChapterManifestError(
                        "pipeline node has no active chapter page"
                    )
                pipeline_nodes[str(edge["node_key"])] = {
                    **dict(edge),
                    "page_url": str(target["page_url"])
                    + (
                        "#" + str(edge["target_anchor_id"])
                        if edge.get("target_anchor_id")
                        else ""
                    ),
                    "display_title": str(target["display_title"]),
                }
        if chapter_manifest_enabled:
            if research_slug == "q2-low-snr-neural-selection-factory":
                landing_document = documents_by_key.get("research-overview")
                review_document = documents_by_key.get("research-backbone")
                group_specs = (
                    ("overview", "研究概览与训练管线", {"overview"}),
                    ("backbone", "理论主干", {"backbone"}),
                    ("vertical", "D1–D6 纵向深化与证据裁决", {"expands", "adjudicates"}),
                    ("cross-cutting", "跨步骤机制", {"unifies"}),
                    ("reference", "术语与历史说明", {"defines", "historical_navigation"}),
                )
                document_groups = [
                    {
                        "key": key,
                        "title": title,
                        "documents": [
                            item
                            for item in page_documents
                            if item["relationship"] in relationships
                        ],
                    }
                    for key, title, relationships in group_specs
                    if any(
                        item["relationship"] in relationships
                        for item in page_documents
                    )
                ]
            else:
                landing_document = page_documents[0] if page_documents else None
                review_document = landing_document
                document_groups = [
                    {
                        "key": "research-backbone",
                        "title": "研究章节",
                        "documents": page_documents,
                    }
                ] if page_documents else []
        else:
            landing_document = (
                documents_by_path.get(str(entry_paths["landing"]))
                if entry_paths["landing"] is not None
                else None
            )
            review_document = (
                documents_by_path.get(str(entry_paths["review"]))
                if entry_paths["review"] is not None
                else None
            )
            document_groups = self.presentation.group_documents(
                research_slug, page_documents
            )
        return {
            "research_id": str(research["research_id"]),
            "canonical_slug": str(research["canonical_slug"]),
            "source_display_title": source_title,
            "display_title": self.presentation.research_title(
                research_slug, source_title
            ),
            "summary": self.presentation.research_summary(research_slug),
            "orientation": self.presentation.research_orientation(research_slug),
            "research_release_id": str(research["research_release_id"]),
            "release_key": str(research["release_key"]),
            "release_revision": int(research["revision"]),
            "work_status": research["work_status"],
            "release_status": research["release_status"],
            "evidence_status": research["evidence_status"],
            "documents": page_documents,
            "documents_by_key": documents_by_key,
            "pipeline_nodes": pipeline_nodes,
            "landing_document": landing_document,
            "review_document": review_document,
            "document_groups": document_groups,
        }

    def research_document_page(
        self, research_id: str, document_id: str
    ) -> dict[str, Any]:
        """返回一个独立研究文档及其同专题导航，不拼接其他 Markdown 正文。"""

        page = self.research_page(research_id, include_rendered=False)
        selected_index: int | None = None
        for index, document in enumerate(page["documents"]):
            if str(document["document_id"]) == document_id:
                selected_index = index
                break
        if selected_index is None:
            raise ArchiveNotFound("active research document not found")
        selected = dict(page["documents"][selected_index])
        if selected["chapters"]:
            return self.research_chapter_page(
                research_id,
                document_id,
                str(selected["chapters"][0]["route_slug"]),
                page=page,
            )
        with archive_connection(self.settings) as connection:
            projection = connection.execute(
                """
                SELECT projection.rendered_object_urn
                FROM document_projection AS projection
                WHERE projection.document_version_id=? AND projection.status='ready'
                """,
                (selected["document_version_id"],),
            ).fetchone()
        if projection is None:
            raise ArchiveNotFound("active research document projection not found")
        selected["rendered_html"] = self.object_store.read_bytes(
            _object_id_from_urn(str(projection["rendered_object_urn"]))
        ).decode("utf-8")
        selected["previous_document"] = (
            page["documents"][selected_index - 1] if selected_index > 0 else None
        )
        selected["next_document"] = (
            page["documents"][selected_index + 1]
            if selected_index + 1 < len(page["documents"])
            else None
        )
        return {**page, "document": selected}

    def research_chapter_page(
        self,
        research_id: str,
        document_id: str,
        chapter_slug: str,
        *,
        page: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return only the sealed source slice for one semantic reading page."""

        current_page = page or self.research_page(research_id, include_rendered=False)
        selected = next(
            (
                dict(item)
                for item in current_page["documents"]
                if str(item["document_id"]) == document_id
            ),
            None,
        )
        if selected is None:
            raise ArchiveNotFound("active research document not found")
        chapters = list(selected.get("chapters") or [])
        chapter_index = next(
            (
                index
                for index, item in enumerate(chapters)
                if str(item["route_slug"]) == chapter_slug
            ),
            None,
        )
        if chapter_index is None:
            raise ArchiveNotFound("active research chapter not found")
        chapter = dict(chapters[chapter_index])
        source_bytes, _slug = self.source_document(research_id, document_id)
        start = int(chapter["absolute_start"])
        end = int(chapter["absolute_end"])
        chapter_bytes = source_bytes[start:end]
        if hashlib.sha256(chapter_bytes).hexdigest() != chapter["source_slice_sha256"]:
            raise ArchiveChapterManifestError("chapter source slice hash mismatch")
        chapter["previous_chapter"] = (
            chapters[chapter_index - 1] if chapter_index > 0 else None
        )
        chapter["next_chapter"] = (
            chapters[chapter_index + 1]
            if chapter_index + 1 < len(chapters)
            else None
        )
        selected.update(
            {
                "toc": chapter["toc"],
                "rendered_html": "",
                "chapter": chapter,
                "previous_document": None,
                "next_document": None,
            }
        )
        return {
            **current_page,
            "document": selected,
            "chapter": chapter,
            "chapter_source_bytes": chapter_bytes,
        }

    def legacy_chapter_redirect_url(
        self, research_id: str, document_id: str, legacy_route_slug: str
    ) -> str | None:
        """将旧的自动切片路由定位到新的语义页及原始标题锚点。"""

        page = self.research_page(research_id, include_rendered=False)
        selected = next(
            (
                item
                for item in page["documents"]
                if str(item["document_id"]) == document_id
            ),
            None,
        )
        if selected is None:
            return None
        manifest = self.chapter_manifests.manifest(str(page["canonical_slug"]))
        if manifest is None:
            return None
        alias = next(
            (
                item
                for item in manifest.get("legacy_chapter_redirects", [])
                if str(item["document_key"]) == str(selected["document_key"])
                and str(item["legacy_route_slug"]) == legacy_route_slug
            ),
            None,
        )
        if alias is None:
            return None
        target = next(
            (
                chapter
                for document in page["documents"]
                for chapter in document.get("chapters", [])
                if str(chapter["chapter_revision_id"])
                == str(alias["target_chapter_revision_id"])
            ),
            None,
        )
        if target is None:
            raise ArchiveChapterManifestError(
                "legacy chapter redirect has no active semantic page"
            )
        anchor_id = str(alias.get("target_anchor_id") or "")
        if anchor_id and anchor_id not in target.get("heading_anchor_ids", ()):
            raise ArchiveChapterManifestError(
                "legacy chapter redirect anchor is outside its semantic page"
            )
        return str(target["page_url"]) + ("#" + anchor_id if anchor_id else "")

    def source_document(self, research_id: str, document_id: str) -> tuple[bytes, str]:
        with archive_connection(self.settings) as connection:
            row = connection.execute(
                """
                SELECT version.object_urn,document.slug
                FROM active_research_release AS active
                JOIN research_release_item AS item
                  ON item.research_release_id=active.research_release_id
                JOIN research_document AS document ON document.document_id=item.document_id
                JOIN research_document_version AS version
                  ON version.document_version_id=item.document_version_id
                WHERE active.research_id=? AND document.document_id=?
                """,
                (research_id, document_id),
            ).fetchone()
        if row is None:
            raise ArchiveNotFound("active research document not found")
        return self.object_store.read_bytes(_object_id_from_urn(str(row["object_urn"]))), str(row["slug"])

    def presentation_asset(self, asset_id: str) -> tuple[bytes, dict[str, Any]]:
        """读取 manifest 明确冻结的非 Markdown Archive 阅读资源。"""

        asset = self.presentation.internal_asset(asset_id)
        if asset is None:
            raise ArchiveNotFound("presentation asset is not approved")
        snapshot = ReadOnlyArchiveAssetSource(self.settings.archive_root).read_verified(
            str(asset["source_path"]),
            expected_sha256=str(asset["sha256"]),
            expected_bytes=int(asset["bytes"]),
        )
        return snapshot.content, asset

    def search(self, query: str, *, limit: int = 30) -> list[dict[str, Any]]:
        query = query.strip()
        if not query:
            return []
        limit = max(1, min(limit, 100))
        like = f"%{query.replace('%', r'\%').replace('_', r'\_')}%"
        hidden = tuple(sorted(self.presentation.hidden_research_slugs))
        hidden_clause = (
            " AND research.canonical_slug NOT IN ("
            + ",".join("?" for _ in hidden)
            + ")"
            if hidden
            else ""
        )
        with archive_connection(self.settings) as connection:
            rows = connection.execute(
                f"""
                SELECT search.research_id,search.document_version_id,search.title_text,
                       search.search_text,research.display_title,research.canonical_slug,
                       document.document_id
                FROM document_search_projection AS search
                JOIN research USING(research_id)
                JOIN research_document_version AS version
                  ON version.document_version_id=search.document_version_id
                JOIN research_document AS document
                  ON document.document_id=version.document_id
                WHERE (search.title_text LIKE ? ESCAPE '\\'
                   OR search.search_text LIKE ? ESCAPE '\\')
                {hidden_clause}
                ORDER BY research.display_title,search.document_version_id
                LIMIT ?
                """,
                (like, like, *hidden, limit),
            ).fetchall()
        results: list[dict[str, Any]] = []
        folded = query.casefold()
        for row in rows:
            text = self.presentation.public_search_text(str(row["search_text"]))
            position = text.casefold().find(folded)
            presented_title = self.presentation.research_title(
                str(row["canonical_slug"]), str(row["display_title"])
            )
            if position < 0 and folded not in presented_title.casefold():
                continue
            if position < 0:
                position = 0
            start = max(0, position - 60)
            end = min(len(text), position + len(query) + 120)
            results.append(
                {
                    "research_id": str(row["research_id"]),
                    "document_version_id": str(row["document_version_id"]),
                    "title": presented_title,
                    "page_url": (
                        f"/research/{row['research_id']}/documents/"
                        f"{row['document_id']}"
                    ),
                    "snippet": ("…" if start else "") + text[start:end] + ("…" if end < len(text) else ""),
                }
            )
        return results
