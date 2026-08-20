from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Literal, Protocol, runtime_checkable
import uuid

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import (
    ArchiveDocumentInput,
    ArchiveReleaseInput,
    ArchiveVersionRelationInput,
)
from quant_hub.archive.database import archive_connection, initialize_archive_database
from quant_hub.archive.markdown import project_markdown
from quant_hub.archive.service import ingest_archive_snapshot, initialize_platform
from quant_hub.archive.source_reader import ReadOnlyArchiveSource, SourceBoundaryError
from quant_hub.config import Settings, ensure_no_reparse_components, stat_is_reparse_point
from quant_hub.ids import new_public_id, sha256_hex, stable_sha256
from quant_hub.platform.db import connect_database, immediate_transaction, utc_now
from quant_hub.platform.objects import ObjectStore
from quant_hub.platform.releases import ReleaseAuthority
from quant_hub.platform.workflow import canonical_json, register_verified_object

from .clues import ClueArtifact, extract_clues


INTAKE_WORKFLOW_VERSION = "1"
NEUTRAL_MAPPING_POLICY_VERSION = "neutral-one-document-mapping/v1"
_STEP_KEYS = (
    "register_source_snapshot",
    "build_neutral_mapping",
    "project_markdown",
    "extract_clues",
    "publish_archive",
    "dispatch_evidence",
)


class IncrementalIntakeError(RuntimeError):
    pass


class _IntakeSkipped(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _IntakeWaitingExternal(RuntimeError):
    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True, slots=True)
class IntakeSource:
    namespace: Literal["archive", "research_inbox"]
    root: Path

    def __post_init__(self) -> None:
        if self.namespace not in {"archive", "research_inbox"}:
            raise ValueError("unsupported intake source namespace")


@dataclass(frozen=True, slots=True)
class EvidenceIngestCommand:
    schema_version: str
    idempotency_key: str
    child_run_urn: str
    parent_run_urn: str
    archive_event_id: str
    research_urn: str
    archive_release_urn: str
    document_version_urn: str
    source_object_urn: str
    source_path: str
    clue_artifact_urn: str
    clue_artifact_sha256: str
    occurrences: tuple[dict[str, Any], ...]

    def payload(self) -> dict[str, Any]:
        value = asdict(self)
        value["occurrences"] = list(self.occurrences)
        return value

    @property
    def command_hash(self) -> str:
        return sha256_hex(canonical_json(self.payload()).encode("utf-8"))


@dataclass(frozen=True, slots=True)
class EvidenceDispatchReceipt:
    schema_version: str
    idempotency_key: str
    child_run_urn: str
    command_hash: str
    status: Literal["accepted", "blocked_external", "terminal_failed"]
    detail: str
    result_hash: str
    created: bool = True

    @staticmethod
    def _result_hash(payload: dict[str, Any]) -> str:
        return sha256_hex(canonical_json(payload).encode("utf-8"))

    @classmethod
    def create(
        cls,
        command: EvidenceIngestCommand,
        *,
        status: Literal["accepted", "blocked_external", "terminal_failed"],
        detail: str,
        created: bool = True,
    ) -> "EvidenceDispatchReceipt":
        material = {
            "schema_version": "qrh-evidence-dispatch-receipt/v1",
            "idempotency_key": command.idempotency_key,
            "child_run_urn": command.child_run_urn,
            "command_hash": command.command_hash,
            "status": status,
            "detail": detail,
        }
        return cls(**material, result_hash=cls._result_hash(material), created=created)

    @classmethod
    def from_dict(cls, value: dict[str, Any], *, created: bool = False) -> "EvidenceDispatchReceipt":
        material = {
            key: value[key]
            for key in (
                "schema_version",
                "idempotency_key",
                "child_run_urn",
                "command_hash",
                "status",
                "detail",
            )
        }
        expected = cls._result_hash(material)
        if value.get("result_hash") != expected:
            raise IncrementalIntakeError("Evidence dispatch receipt hash is invalid")
        return cls(**material, result_hash=expected, created=created)

    def verify(self, command: EvidenceIngestCommand) -> None:
        if self.schema_version != "qrh-evidence-dispatch-receipt/v1":
            raise IncrementalIntakeError("Evidence adapter returned an unsupported receipt")
        if (
            self.idempotency_key != command.idempotency_key
            or self.child_run_urn != command.child_run_urn
            or self.command_hash != command.command_hash
        ):
            raise IncrementalIntakeError("Evidence receipt is not bound to the dispatched command")
        material = {
            "schema_version": self.schema_version,
            "idempotency_key": self.idempotency_key,
            "child_run_urn": self.child_run_urn,
            "command_hash": self.command_hash,
            "status": self.status,
            "detail": self.detail,
        }
        if self.result_hash != self._result_hash(material):
            raise IncrementalIntakeError("Evidence receipt material was altered")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class EvidenceIngestAdapter(Protocol):
    def dispatch(self, command: EvidenceIngestCommand) -> EvidenceDispatchReceipt: ...


def _atomic_immutable_write(path: Path, payload: bytes) -> bool:
    ensure_no_reparse_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(path.parent)
    if os.path.lexists(path):
        info = path.lstat()
        if stat_is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise IncrementalIntakeError("managed receipt path is not a regular single-link file")
        if path.read_bytes() != payload:
            raise IncrementalIntakeError("immutable managed artifact conflicts with existing bytes")
        return False
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    if path.read_bytes() != payload:
        raise IncrementalIntakeError("atomic managed artifact verification failed")
    return True


class LocalSpoolEvidenceAdapter:
    """显式 transport-only 适配器；只冻结命令，不能伪装成目标域接收。"""

    def __init__(self, settings: Settings, spool_root: Path | None = None):
        self.root = (spool_root or settings.var_root / "integration" / "evidence_commands").absolute()
        try:
            self.root.relative_to(settings.var_root.absolute())
        except ValueError as error:
            raise ValueError("Evidence command spool must stay inside var_root") from error

    def dispatch(self, command: EvidenceIngestCommand) -> EvidenceDispatchReceipt:
        ensure_no_reparse_components(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        command_bytes = canonical_json(command.payload()).encode("utf-8")
        command_path = self.root / f"{command.idempotency_key}.command.json"
        _atomic_immutable_write(command_path, command_bytes)
        receipt = EvidenceDispatchReceipt.create(
            command,
            status="blocked_external",
            detail=(
                "transport-only spool 已冻结命令，但 Evidence 目标域尚未持久化；"
                "父编排保持 waiting_external。"
            ),
        )
        receipt_payload = receipt.to_dict()
        receipt_payload.pop("created", None)
        receipt_path = self.root / f"{command.idempotency_key}.receipt.json"
        created = _atomic_immutable_write(
            receipt_path, canonical_json(receipt_payload).encode("utf-8")
        )
        if not created:
            stored = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt = EvidenceDispatchReceipt.from_dict(stored, created=False)
        receipt.verify(command)
        return receipt


@dataclass(frozen=True, slots=True)
class IntakeItemResult:
    namespace: str
    relative_path: str
    source_sha256: str
    source_bytes: int
    parent_run_id: str
    parent_created: bool
    research_id: str
    research_slug: str
    research_release_id: str
    release_revision: int
    document_version_id: str
    clue_artifact_urn: str
    clue_count: int
    evidence_child_run_urn: str
    evidence_dispatch_status: str
    evidence_receipt_hash: str
    state: Literal["published", "aliased", "unchanged"]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class IntakeIssue:
    namespace: str
    relative_path: str
    code: str
    error_type: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class IntakeSkip:
    namespace: str
    relative_path: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class IntakeReport:
    schema_version: str
    status: Literal["PASS", "PARTIAL", "ERROR"]
    started_at: str
    completed_at: str
    processed: tuple[IntakeItemResult, ...]
    skipped: tuple[IntakeSkip, ...]
    issues: tuple[IntakeIssue, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "counts": {
                "processed": len(self.processed),
                "published": sum(item.state == "published" for item in self.processed),
                "aliased": sum(item.state == "aliased" for item in self.processed),
                "unchanged": sum(item.state == "unchanged" for item in self.processed),
                "skipped": len(self.skipped),
                "issues": len(self.issues),
            },
            "processed": [item.to_dict() for item in self.processed],
            "skipped": [item.to_dict() for item in self.skipped],
            "issues": [item.to_dict() for item in self.issues],
        }


def _enumerate_markdown(root: Path) -> tuple[list[str], list[IntakeIssue]]:
    paths: list[str] = []
    issues: list[IntakeIssue] = []
    reader = ReadOnlyArchiveSource(root)
    pending = [reader.root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda item: (item.name.casefold(), item.name))
        children: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(reader.root).as_posix()
            try:
                info = entry.stat(follow_symlinks=False)
                if stat_is_reparse_point(info):
                    if stat.S_ISDIR(info.st_mode) or path.suffix.lower() in {".md", ".markdown"}:
                        issues.append(
                            IntakeIssue("unknown", relative, "reparse_rejected", "SourceBoundaryError", "不跟随 reparse/symlink 来源。")
                        )
                    continue
                if stat.S_ISDIR(info.st_mode):
                    children.append(path)
                elif path.suffix.lower() in {".md", ".markdown"}:
                    if stat.S_ISREG(info.st_mode):
                        paths.append(relative)
                    else:
                        issues.append(
                            IntakeIssue("unknown", relative, "non_regular_markdown", "SourceBoundaryError", "Markdown 来源不是普通文件。")
                        )
            except OSError as error:
                issues.append(
                    IntakeIssue("unknown", relative, "source_stat_failed", type(error).__name__, str(error))
                )
        pending.extend(reversed(children))
    return sorted(paths, key=lambda value: (value.casefold(), value)), issues


class IncrementalIntake:
    """稳定 Markdown → Archive release → Evidence command 的可恢复父编排器。"""

    def __init__(
        self,
        settings: Settings,
        evidence_adapter: EvidenceIngestAdapter | None = None,
        *,
        source_view_root: Path | None = None,
    ):
        self.settings = settings
        if evidence_adapter is None:
            # 延迟导入避免 Evidence adapter 的 Protocol 类型导入形成模块初始化环。
            from quant_hub.evidence.ingest import EvidenceDatabaseIngestAdapter

            evidence_adapter = EvidenceDatabaseIngestAdapter(settings)
        self.evidence_adapter = evidence_adapter
        self.source_view_root = (
            source_view_root
            or settings.var_root / "integration" / "source_views"
        ).absolute()
        try:
            self.source_view_root.relative_to(settings.var_root.absolute())
        except ValueError as error:
            raise ValueError("managed intake source view must stay inside var_root") from error

    def _store_json(self, payload: dict[str, Any], media_type: str) -> tuple[str, str]:
        body = canonical_json(payload).encode("utf-8")
        stored = ObjectStore(self.settings.object_root).put_bytes(body)
        connection = connect_database(self.settings.database_path)
        try:
            register_verified_object(
                connection,
                stored,
                ObjectStore(self.settings.object_root),
                media_type=media_type,
            )
        finally:
            connection.close()
        return f"qrh:object:{stored.object_id}", stored.sha256

    def _materialize_source(
        self, source: IntakeSource, relative_path: str
    ) -> tuple[Settings, str, bytes, str]:
        snapshot = ReadOnlyArchiveSource(source.root).snapshot(relative_path)
        if source.namespace == "archive" and source.root.resolve() == self.settings.archive_root.resolve():
            return self.settings, relative_path, snapshot.content, snapshot.sha256
        namespace_path = source.namespace.replace("_", "-")
        view_relative = f"{namespace_path}/{relative_path}"
        pure = PurePosixPath(view_relative)
        if any(part in {"", ".", ".."} for part in pure.parts):
            raise SourceBoundaryError("intake source view path is unsafe")
        ensure_no_reparse_components(self.source_view_root)
        self.source_view_root.mkdir(parents=True, exist_ok=True)
        target = self.source_view_root.joinpath(*pure.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(target.parent)
        existing_payload: bytes | None = None
        if os.path.lexists(target):
            info = target.lstat()
            if stat_is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SourceBoundaryError("managed source view target is not a regular file")
            existing_payload = target.read_bytes()
        if existing_payload != snapshot.content:
            temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
            try:
                with temporary.open("xb") as handle:
                    handle.write(snapshot.content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
        if target.read_bytes() != snapshot.content:
            raise SourceBoundaryError("managed source view differs from stable source bytes")
        # 这是 integration 内部的受管兼容视图，不是新的用户配置。Archive 服务只在
        # 本次调用中从它读取已复核字节；所有数据库/对象路径仍使用原 Settings。
        # 因视图本身位于 var_root，不能调用面向外部只读来源的 Settings.validate()。
        derived = replace(self.settings, archive_root=self.source_view_root)
        return derived, view_relative, snapshot.content, snapshot.sha256

    @staticmethod
    def _source_key(namespace: str, relative_path: str) -> str:
        return f"{namespace}:///{relative_path}"

    def _ensure_parent_run(
        self,
        *,
        registration: Any,
        source_key: str,
        source_sha256: str,
    ) -> tuple[str, bool, str]:
        input_hash = stable_sha256(
            "archive-import-input/v1", source_key, source_sha256, registration.object_id
        )
        idempotency_key = stable_sha256(
            "archive-import-run/v1", source_key, source_sha256, NEUTRAL_MAPPING_POLICY_VERSION
        )
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                row = connection.execute(
                    "SELECT * FROM pipeline_run WHERE idempotency_key=?", (idempotency_key,)
                ).fetchone()
                created = row is None
                if row is None:
                    run_id = new_public_id("run")
                    now = utc_now()
                    connection.execute(
                        """
                        INSERT INTO pipeline_run(
                            run_id,workflow_name,workflow_version,subject_urn,input_manifest_hash,
                            idempotency_key,run_status,release_status,created_at,started_at,finished_at
                        ) VALUES(?,?,?,?,?,?,'running','staging',?,?,NULL)
                        """,
                        (
                            run_id,
                            "archive_import",
                            INTAKE_WORKFLOW_VERSION,
                            f"qrh:intake-source:{stable_sha256(source_key)}",
                            input_hash,
                            idempotency_key,
                            now,
                            now,
                        ),
                    )
                    dependency = input_hash
                    for index, step_key in enumerate(_STEP_KEYS):
                        status = "succeeded" if index == 0 else "waiting"
                        output = (
                            stable_sha256(
                                "archive-import-snapshot/v1",
                                registration.object_id,
                                registration.source_location_id,
                                registration.run_id,
                            )
                            if index == 0
                            else None
                        )
                        connection.execute(
                            """
                            INSERT INTO step_execution(
                                step_execution_id,run_id,step_key,step_version,
                                dependency_manifest_hash,required_for_release,status,
                                output_manifest_hash,created_at,finished_at
                            ) VALUES(?,?,?,?,?,1,?,?,?,?)
                            """,
                            (
                                new_public_id("step"),
                                run_id,
                                step_key,
                                "1",
                                dependency,
                                status,
                                output,
                                now,
                                now if index == 0 else None,
                            ),
                        )
                        dependency = output or stable_sha256(dependency, step_key)
                    self._insert_platform_event(
                        connection,
                        "ArchiveImportStarted",
                        f"qrh:run:{run_id}",
                        {
                            "run_urn": f"qrh:run:{run_id}",
                            "source_key": source_key,
                            "source_sha256": source_sha256,
                            "source_snapshot_run_urn": f"qrh:run:{registration.run_id}",
                        },
                    )
                else:
                    run_id = str(row["run_id"])
                    if (
                        row["workflow_name"] != "archive_import"
                        or row["workflow_version"] != INTAKE_WORKFLOW_VERSION
                        or row["input_manifest_hash"] != input_hash
                    ):
                        raise IncrementalIntakeError("archive import idempotency key conflicts")
                    if row["run_status"] == "failed":
                        connection.execute(
                            "UPDATE pipeline_run SET run_status='running',started_at=?,finished_at=NULL WHERE run_id=?",
                            (utc_now(), run_id),
                        )
                        self._insert_platform_event(
                            connection,
                            "ArchiveImportResumed",
                            f"qrh:run:{run_id}",
                            {"run_urn": f"qrh:run:{run_id}", "source_sha256": source_sha256},
                        )
                return run_id, created, str(row["run_status"] if row is not None else "running")
        finally:
            connection.close()

    def _parent_exists(self, *, source_key: str, source_sha256: str) -> bool:
        key = stable_sha256(
            "archive-import-run/v1",
            source_key,
            source_sha256,
            NEUTRAL_MAPPING_POLICY_VERSION,
        )
        connection = connect_database(self.settings.database_path)
        try:
            return connection.execute(
                "SELECT 1 FROM pipeline_run WHERE idempotency_key=?", (key,)
            ).fetchone() is not None
        finally:
            connection.close()

    @staticmethod
    def _verified_origin_mappings(
        settings: Settings, source_location_id: str
    ) -> tuple[dict[str, str], ...]:
        platform = connect_database(settings.database_path)
        try:
            source = platform.execute(
                "SELECT namespace,origin_uri FROM source_location WHERE source_location_id=?",
                (source_location_id,),
            ).fetchone()
            if source is None:
                raise IncrementalIntakeError("source location disappeared")
            source_ids = [
                str(row["source_location_id"])
                for row in platform.execute(
                    """
                    SELECT source_location_id FROM source_location
                    WHERE namespace=? AND origin_uri=?
                    """,
                    (source["namespace"], source["origin_uri"]),
                )
            ]
        finally:
            platform.close()
        if not source_ids:
            return ()
        placeholders = ",".join("?" for _ in source_ids)
        urns = [f"qrh:source:{value}" for value in source_ids]
        with archive_connection(settings) as connection:
            rows = connection.execute(
                f"""
                SELECT DISTINCT research.canonical_slug AS research_slug,
                       document.slug AS document_slug,
                       document.document_role
                FROM research_document_origin AS origin
                JOIN research_document AS document USING(document_id)
                JOIN research USING(research_id)
                WHERE origin.mapping_status='verified'
                  AND origin.source_location_urn IN ({placeholders})
                ORDER BY research.canonical_slug,document.slug
                """,
                urns,
            ).fetchall()
        return tuple(dict(row) for row in rows)

    @staticmethod
    def _insert_platform_event(
        connection: Any, event_type: str, aggregate_urn: str, payload: dict[str, Any]
    ) -> None:
        payload_json = canonical_json(payload)
        payload_hash = stable_sha256("integration-outbox/v1", payload_json)
        connection.execute(
            """
            INSERT INTO outbox_event(
                event_id,event_type,event_version,aggregate_urn,payload_json,
                payload_hash,created_at,published_at
            ) VALUES(?,?,?,?,?,?,?,NULL)
            ON CONFLICT(event_type,aggregate_urn,payload_hash) DO NOTHING
            """,
            (
                new_public_id("evt"),
                event_type,
                "1",
                aggregate_urn,
                payload_json,
                payload_hash,
                utc_now(),
            ),
        )

    def _completed_result(
        self,
        run_id: str,
        *,
        registration: Any,
        namespace: str,
        relative_path: str,
        source_key: str,
        source_sha256: str,
        source_payload: bytes,
    ) -> IntakeItemResult | None:
        """只接受仍与真实来源、Archive 与 Evidence receipt 一致的完成凭据。

        该路径会在每次幂等重放时执行，不能把历史 outbox JSON 当作可信缓存；
        它也覆盖在 append-only migration 生效前可能已经遭修改的旧数据库。
        """

        connection = connect_database(self.settings.database_path)
        try:
            run = connection.execute(
                "SELECT * FROM pipeline_run WHERE run_id=?", (run_id,)
            ).fetchone()
            if run is None or run["run_status"] != "succeeded":
                return None
            expected_subject = f"qrh:intake-source:{stable_sha256(source_key)}"
            expected_input = stable_sha256(
                "archive-import-input/v1",
                source_key,
                source_sha256,
                registration.object_id,
            )
            if (
                run["workflow_name"] != "archive_import"
                or run["workflow_version"] != INTAKE_WORKFLOW_VERSION
                or run["subject_urn"] != expected_subject
                or run["input_manifest_hash"] != expected_input
                or run["release_status"] != "released"
            ):
                raise IncrementalIntakeError("completed archive import run material is inconsistent")
            rows = connection.execute(
                """
                SELECT * FROM outbox_event
                WHERE event_type='ArchiveImportCompleted' AND aggregate_urn=?
                ORDER BY created_at,event_id
                """,
                (f"qrh:run:{run_id}",),
            ).fetchall()
            if len(rows) != 1:
                raise IncrementalIntakeError("completed archive import lacks one completion receipt")
            event = rows[0]
            payload_json = str(event["payload_json"])
            if (
                event["event_version"] != "1"
                or event["payload_hash"]
                != stable_sha256("integration-outbox/v1", payload_json)
            ):
                raise IncrementalIntakeError("completion outbox material hash is invalid")
            try:
                payload = json.loads(payload_json)
            except (TypeError, ValueError) as error:
                raise IncrementalIntakeError("completion outbox payload is invalid JSON") from error
            if payload_json != canonical_json(payload):
                raise IncrementalIntakeError("completion outbox payload is not canonical")
            if not isinstance(payload, dict) or payload.get("run_urn") != f"qrh:run:{run_id}":
                raise IncrementalIntakeError("completion outbox is not bound to its parent run")
            try:
                stored = IntakeItemResult(**dict(payload["item"]))
            except (KeyError, TypeError, ValueError) as error:
                raise IncrementalIntakeError("completion item contract is invalid") from error
            if (
                stored.parent_run_id != run_id
                or stored.namespace != namespace
                or stored.relative_path != relative_path
                or stored.source_sha256 != source_sha256
                or stored.source_bytes != len(source_payload)
                or stored.state not in {"published", "aliased"}
            ):
                raise IncrementalIntakeError("completion item differs from the current source input")

            source_row = connection.execute(
                """
                SELECT source.object_id,object.sha256,object.bytes,object.verification_status
                FROM source_location AS source
                JOIN object_blob AS object USING(object_id)
                WHERE source.source_location_id=?
                """,
                (registration.source_location_id,),
            ).fetchone()
            if source_row is None or (
                str(source_row["object_id"]),
                str(source_row["sha256"]),
                int(source_row["bytes"]),
                str(source_row["verification_status"]),
            ) != (
                registration.object_id,
                source_sha256,
                len(source_payload),
                "verified",
            ):
                raise IncrementalIntakeError("completion source registry material is inconsistent")
            if ObjectStore(self.settings.object_root).read_bytes(registration.object_id) != source_payload:
                raise IncrementalIntakeError("completion source object bytes are inconsistent")

            steps = {
                str(row["step_key"]): row
                for row in connection.execute(
                    "SELECT step_key,status,output_manifest_hash FROM step_execution WHERE run_id=?",
                    (run_id,),
                )
            }
            if set(steps) != set(_STEP_KEYS) or any(
                row["status"] != "succeeded" or row["output_manifest_hash"] is None
                for row in steps.values()
            ):
                raise IncrementalIntakeError("completion parent steps are not fully materialized")
            if stored.state == "published" and (
                steps["dispatch_evidence"]["output_manifest_hash"]
                != stored.evidence_receipt_hash
            ):
                raise IncrementalIntakeError("completion Evidence step differs from its receipt")

            child_prefix = "qrh:run:"
            if not stored.evidence_child_run_urn.startswith(child_prefix):
                raise IncrementalIntakeError("completion Evidence child run URN is invalid")
            child_run_id = stored.evidence_child_run_urn[len(child_prefix) :]
            child = connection.execute(
                """
                SELECT workflow_name,workflow_version,subject_urn,idempotency_key
                FROM pipeline_run WHERE run_id=?
                """,
                (child_run_id,),
            ).fetchone()
            dispatch_rows = connection.execute(
                """
                SELECT * FROM outbox_event
                WHERE event_type='EvidenceIngestDispatchRecorded' AND aggregate_urn=?
                ORDER BY created_at,event_id
                """,
                (stored.evidence_child_run_urn,),
            ).fetchall()
            if child is None or child["workflow_name"] != "evidence_ingest" or len(dispatch_rows) != 1:
                raise IncrementalIntakeError("completion Evidence child material is missing")
            dispatch_event = dispatch_rows[0]
            dispatch_json = str(dispatch_event["payload_json"])
            if (
                dispatch_event["event_version"] != "1"
                or dispatch_event["payload_hash"]
                != stable_sha256("integration-outbox/v1", dispatch_json)
            ):
                raise IncrementalIntakeError("completion Evidence dispatch event hash is invalid")
            try:
                dispatch_payload = json.loads(dispatch_json)
                dispatch_receipt = EvidenceDispatchReceipt.from_dict(dispatch_payload)
            except (KeyError, TypeError, ValueError) as error:
                raise IncrementalIntakeError("completion Evidence dispatch receipt is invalid") from error
            if (
                dispatch_json != canonical_json(dispatch_payload)
                or dispatch_receipt.child_run_urn != stored.evidence_child_run_urn
                or dispatch_receipt.status != stored.evidence_dispatch_status
                or dispatch_receipt.result_hash != stored.evidence_receipt_hash
            ):
                raise IncrementalIntakeError("completion Evidence dispatch receipt has drifted")
        finally:
            connection.close()

        with archive_connection(self.settings) as archive:
            if stored.state == "published":
                archive_rows = archive.execute(
                    """
                    SELECT research.research_id,research.canonical_slug,
                           active.research_release_id,active.revision,
                           document.document_id,version.document_version_id,
                           version.object_urn,version.content_sha256,version.bytes,
                           origin.mapping_status
                    FROM research
                    JOIN active_research_release AS active USING(research_id)
                    JOIN research_release_item AS item USING(research_release_id)
                    JOIN research_document AS document ON document.document_id=item.document_id
                    JOIN research_document_version AS version
                      ON version.document_version_id=item.document_version_id
                    JOIN research_document_origin AS origin
                      ON origin.document_id=document.document_id
                     AND origin.source_location_urn=?
                    WHERE research.research_id=?
                      AND active.research_release_id=?
                      AND version.document_version_id=?
                    """,
                    (
                        f"qrh:source:{registration.source_location_id}",
                        stored.research_id,
                        stored.research_release_id,
                        stored.document_version_id,
                    ),
                ).fetchall()
            else:
                archive_rows = archive.execute(
                    """
                    SELECT research.research_id,research.canonical_slug,
                           active.research_release_id,active.revision,
                           document.document_id,version.document_version_id,
                           version.object_urn,version.content_sha256,version.bytes,
                           origin.mapping_status
                    FROM research
                    JOIN active_research_release AS active USING(research_id)
                    JOIN research_document AS document USING(research_id)
                    JOIN research_document_version AS version USING(document_id)
                    JOIN research_document_origin AS origin
                      ON origin.document_id=document.document_id
                     AND origin.source_location_urn=?
                    WHERE research.research_id=?
                      AND active.research_release_id=?
                      AND version.document_version_id=?
                    """,
                    (
                        f"qrh:source:{registration.source_location_id}",
                        stored.research_id,
                        stored.research_release_id,
                        stored.document_version_id,
                    ),
                ).fetchall()
        if len(archive_rows) != 1:
            raise IncrementalIntakeError("completion Archive release/origin material is missing")
        archive_row = archive_rows[0]
        if (
            archive_row["canonical_slug"] != stored.research_slug
            or int(archive_row["revision"]) != stored.release_revision
            or archive_row["object_urn"] != f"qrh:object:{registration.object_id}"
            or archive_row["content_sha256"] != source_sha256
            or int(archive_row["bytes"]) != len(source_payload)
            or archive_row["mapping_status"] != "verified"
        ):
            raise IncrementalIntakeError("completion Archive release material has drifted")

        clue_prefix = "qrh:object:"
        if not stored.clue_artifact_urn.startswith(clue_prefix):
            raise IncrementalIntakeError("completion clue artifact URN is invalid")
        clue_object_id = stored.clue_artifact_urn[len(clue_prefix) :]
        clue_bytes = ObjectStore(self.settings.object_root).read_bytes(clue_object_id)
        clue_digest = sha256_hex(clue_bytes)
        if (
            clue_object_id != f"obj_sha256_{clue_digest}"
            or steps["extract_clues"]["output_manifest_hash"] != clue_digest
        ):
            raise IncrementalIntakeError("completion clue artifact identity is invalid")
        try:
            clue_payload = json.loads(clue_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise IncrementalIntakeError("completion clue artifact is invalid") from error
        if (
            clue_bytes.decode("utf-8") != canonical_json(clue_payload)
            or clue_payload.get("document_sha256") != source_sha256
            or clue_payload.get("source_object_urn") != f"qrh:object:{registration.object_id}"
            or clue_payload.get("source_path") != f"{namespace}:///{relative_path}"
            or len(clue_payload.get("occurrences", ())) != stored.clue_count
        ):
            raise IncrementalIntakeError("completion clue artifact differs from the current source")

        if stored.state == "aliased":
            expected_noop = stable_sha256(
                "evidence-source-alias-noop/v1",
                stored.evidence_receipt_hash,
                registration.source_location_id,
                clue_digest,
            )
            if steps["dispatch_evidence"]["output_manifest_hash"] != expected_noop:
                raise IncrementalIntakeError("completion alias no-op is not bound to its source")
        elif stored.evidence_dispatch_status == "accepted":
            verifier = getattr(self.evidence_adapter, "verify_persisted_receipt", None)
            if callable(verifier):
                verified = verifier(
                    idempotency_key=str(child["idempotency_key"]),
                    expected_result_hash=stored.evidence_receipt_hash,
                    expected_child_run_urn=stored.evidence_child_run_urn,
                    expected_parent_run_urn=f"qrh:run:{run_id}",
                    expected_research_urn=f"qrh:archive-research:{stored.research_slug}",
                    expected_clue_artifact_urn=stored.clue_artifact_urn,
                )
                if (
                    verified.status != "accepted"
                    or verified.result_hash != stored.evidence_receipt_hash
                ):
                    raise IncrementalIntakeError(
                        "completion Evidence target verification returned another receipt"
                    )

        return replace(stored, parent_created=False, state="unchanged")

    def _begin_step(self, run_id: str, step_key: str) -> None:
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                row = connection.execute(
                    "SELECT status FROM step_execution WHERE run_id=? AND step_key=?",
                    (run_id, step_key),
                ).fetchone()
                if row is None:
                    raise IncrementalIntakeError(f"missing parent step: {step_key}")
                if row["status"] != "succeeded":
                    connection.execute(
                        "UPDATE step_execution SET status='running',finished_at=NULL WHERE run_id=? AND step_key=?",
                        (run_id, step_key),
                    )
        finally:
            connection.close()

    def _finish_step(self, run_id: str, step_key: str, output_hash: str) -> None:
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                row = connection.execute(
                    "SELECT status,output_manifest_hash FROM step_execution WHERE run_id=? AND step_key=?",
                    (run_id, step_key),
                ).fetchone()
                if row is None:
                    raise IncrementalIntakeError(f"missing parent step: {step_key}")
                if row["status"] == "succeeded":
                    if row["output_manifest_hash"] != output_hash:
                        raise IncrementalIntakeError(f"step output drift: {step_key}")
                    return
                connection.execute(
                    """
                    UPDATE step_execution SET status='succeeded',output_manifest_hash=?,finished_at=?
                    WHERE run_id=? AND step_key=?
                    """,
                    (output_hash, utc_now(), run_id, step_key),
                )
        finally:
            connection.close()

    def _fail_parent(self, run_id: str, step_key: str, error: Exception) -> None:
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                connection.execute(
                    "UPDATE step_execution SET status='failed',finished_at=? WHERE run_id=? AND step_key=? AND status<>'succeeded'",
                    (utc_now(), run_id, step_key),
                )
                connection.execute(
                    "UPDATE pipeline_run SET run_status='failed',finished_at=? WHERE run_id=?",
                    (utc_now(), run_id),
                )
                self._insert_platform_event(
                    connection,
                    "ArchiveImportFailed",
                    f"qrh:run:{run_id}",
                    {
                        "run_urn": f"qrh:run:{run_id}",
                        "step_key": step_key,
                        "error_type": type(error).__name__,
                        "detail": str(error),
                    },
                )
        finally:
            connection.close()

    def _block_parent(
        self, run_id: str, step_key: str, receipt: EvidenceDispatchReceipt
    ) -> None:
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                connection.execute(
                    """
                    UPDATE step_execution
                    SET status='blocked',output_manifest_hash=?,finished_at=?
                    WHERE run_id=? AND step_key=? AND status<>'succeeded'
                    """,
                    (receipt.result_hash, utc_now(), run_id, step_key),
                )
                connection.execute(
                    """
                    UPDATE pipeline_run
                    SET run_status='waiting_external',finished_at=NULL
                    WHERE run_id=?
                    """,
                    (run_id,),
                )
                self._insert_platform_event(
                    connection,
                    "ArchiveImportWaitingExternal",
                    f"qrh:run:{run_id}",
                    {
                        "run_urn": f"qrh:run:{run_id}",
                        "step_key": step_key,
                        "receipt_hash": receipt.result_hash,
                        "detail": receipt.detail,
                    },
                )
        finally:
            connection.close()

    @staticmethod
    def _previous_content(settings: Settings, research_slug: str) -> str | None:
        try:
            with archive_connection(settings) as connection:
                row = connection.execute(
                    """
                    SELECT version.content_sha256
                    FROM research
                    JOIN active_research_release AS active USING(research_id)
                    JOIN research_release_item AS item USING(research_release_id)
                    JOIN research_document AS document USING(document_id)
                    JOIN research_document_version AS version USING(document_version_id)
                    WHERE research.canonical_slug=? AND document.slug='main'
                    """,
                    (research_slug,),
                ).fetchone()
                return str(row["content_sha256"]) if row else None
        except Exception as error:
            if "no such table" in str(error):
                return None
            raise

    def _ensure_child_run(
        self, *, idempotency_key: str, subject_urn: str, input_hash: str
    ) -> tuple[str, bool]:
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                row = connection.execute(
                    "SELECT * FROM pipeline_run WHERE idempotency_key=?", (idempotency_key,)
                ).fetchone()
                if row is not None:
                    if (
                        row["workflow_name"] != "evidence_ingest"
                        or row["workflow_version"] != "1"
                        or row["subject_urn"] != subject_urn
                        or row["input_manifest_hash"] != input_hash
                    ):
                        raise IncrementalIntakeError("Evidence child run identity conflicts")
                    return str(row["run_id"]), False
                run_id = new_public_id("run")
                now = utc_now()
                connection.execute(
                    """
                    INSERT INTO pipeline_run(
                        run_id,workflow_name,workflow_version,subject_urn,input_manifest_hash,
                        idempotency_key,run_status,release_status,created_at,started_at,finished_at
                    ) VALUES(?,?,?,?,?,?,'queued','staging',?,NULL,NULL)
                    """,
                    (run_id, "evidence_ingest", "1", subject_urn, input_hash, idempotency_key, now),
                )
                for key, status in (
                    ("consume_archive_document_event", "runnable"),
                    ("evidence_pipeline", "waiting"),
                ):
                    connection.execute(
                        """
                        INSERT INTO step_execution(
                            step_execution_id,run_id,step_key,step_version,
                            dependency_manifest_hash,required_for_release,status,
                            output_manifest_hash,created_at,finished_at
                        ) VALUES(?,?,?,?,?,1,?,NULL,?,NULL)
                        """,
                        (new_public_id("step"), run_id, key, "1", input_hash, status, now),
                    )
                return run_id, True
        finally:
            connection.close()

    def _record_child_receipt(
        self, child_run_id: str, receipt: EvidenceDispatchReceipt
    ) -> None:
        if receipt.status == "accepted":
            run_status, pipeline_status = "queued", "runnable"
        elif receipt.status == "blocked_external":
            run_status, pipeline_status = "waiting_external", "blocked"
        else:
            run_status, pipeline_status = "failed", "failed"
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                existing = connection.execute(
                    """
                    SELECT status,output_manifest_hash FROM step_execution
                    WHERE run_id=? AND step_key='consume_archive_document_event'
                    """,
                    (child_run_id,),
                ).fetchone()
                if existing is None:
                    raise IncrementalIntakeError("Evidence child receipt step is missing")
                if (
                    existing["status"] == "succeeded"
                    and existing["output_manifest_hash"] != receipt.result_hash
                ):
                    raise IncrementalIntakeError("Evidence child receipt conflicts with prior result")
                connection.execute(
                    """
                    UPDATE step_execution
                    SET status='succeeded',output_manifest_hash=?,finished_at=?
                    WHERE run_id=? AND step_key='consume_archive_document_event'
                    """,
                    (receipt.result_hash, utc_now(), child_run_id),
                )
                connection.execute(
                    "UPDATE step_execution SET status=? WHERE run_id=? AND step_key='evidence_pipeline' AND status<>'succeeded'",
                    (pipeline_status, child_run_id),
                )
                connection.execute(
                    "UPDATE pipeline_run SET run_status=?,started_at=COALESCE(started_at,?) WHERE run_id=?",
                    (run_status, utc_now(), child_run_id),
                )
                receipt_payload = receipt.to_dict()
                receipt_payload.pop("created", None)
                self._insert_platform_event(
                    connection,
                    "EvidenceIngestDispatchRecorded",
                    f"qrh:run:{child_run_id}",
                    receipt_payload,
                )
        finally:
            connection.close()

    @staticmethod
    def _archive_document_event(
        settings: Settings, document_version_id: str
    ) -> tuple[str, dict[str, Any]]:
        with archive_connection(settings) as connection:
            rows = connection.execute(
                """
                SELECT * FROM outbox_event
                WHERE event_type='ArchiveDocumentVersionRegistered'
                  AND json_extract(payload_json,'$.document_version_id')=?
                """,
                (document_version_id,),
            ).fetchall()
        if len(rows) != 1:
            raise IncrementalIntakeError("Archive document version event is missing or duplicated")
        event = rows[0]
        payload_json = str(event["payload_json"])
        if (
            event["event_version"] != "1"
            or event["payload_hash"] != stable_sha256("archive-outbox/v1", payload_json)
        ):
            raise IncrementalIntakeError("Archive document event material hash is invalid")
        payload = json.loads(payload_json)
        if payload_json != canonical_json(payload):
            raise IncrementalIntakeError("Archive document event payload is not canonical")
        return str(event["event_id"]), payload

    @staticmethod
    def _mark_archive_event_delivered(
        settings: Settings,
        *,
        event_id: str,
        document_version_id: str,
        receipt: EvidenceDispatchReceipt,
    ) -> None:
        if receipt.status != "accepted":
            raise IncrementalIntakeError(
                "Archive event can only be acknowledged by an accepted target receipt"
            )
        with archive_connection(settings) as connection, immediate_transaction(connection):
            event = connection.execute(
                "SELECT * FROM outbox_event WHERE event_id=?", (event_id,)
            ).fetchone()
            if event is None or event["event_type"] != "ArchiveDocumentVersionRegistered":
                raise IncrementalIntakeError("Archive relay source event is missing")
            payload_json = str(event["payload_json"])
            try:
                payload = json.loads(payload_json)
            except (TypeError, ValueError) as error:
                raise IncrementalIntakeError("Archive relay source event JSON is invalid") from error
            if (
                event["event_version"] != "1"
                or event["payload_hash"]
                != stable_sha256("archive-outbox/v1", payload_json)
                or payload_json != canonical_json(payload)
                or payload.get("document_version_id") != document_version_id
            ):
                raise IncrementalIntakeError(
                    "Archive relay source event is not bound to the accepted command"
                )
            connection.execute(
                """
                UPDATE outbox_event
                SET published_at=COALESCE(published_at,?),
                    publish_attempt_count=publish_attempt_count+1
                WHERE event_id=?
                """,
                (utc_now(), event_id),
            )

    @staticmethod
    def _acknowledge_evidence_result(
        settings: Settings,
        *,
        adapter: EvidenceIngestAdapter,
        command: EvidenceIngestCommand,
        receipt: EvidenceDispatchReceipt,
    ) -> None:
        event_identity = getattr(adapter, "result_event_id", None)
        acknowledge = getattr(adapter, "acknowledge_result", None)
        if event_identity is None and acknowledge is None:
            return
        if not callable(event_identity) or not callable(acknowledge):
            raise IncrementalIntakeError(
                "Evidence adapter exposes an incomplete result acknowledgement contract"
            )
        consumer_name = getattr(adapter, "RESULT_CONSUMER_NAME", None)
        if not isinstance(consumer_name, str) or not consumer_name:
            raise IncrementalIntakeError("Evidence result consumer identity is missing")
        event_id = str(event_identity(command))
        with archive_connection(settings) as connection, immediate_transaction(connection):
            existing = connection.execute(
                """
                SELECT result_hash FROM inbox_receipt
                WHERE consumer_name=? AND source_domain='evidence' AND event_id=?
                """,
                (consumer_name, event_id),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO inbox_receipt(
                        consumer_name,source_domain,event_id,processed_at,result_hash
                    ) VALUES(?,'evidence',?,?,?)
                    """,
                    (consumer_name, event_id, utc_now(), receipt.result_hash),
                )
            elif existing["result_hash"] != receipt.result_hash:
                raise IncrementalIntakeError(
                    "Archive inbox already binds the Evidence result differently"
                )
        acknowledge(command, receipt)

    @staticmethod
    def _project_dispatch_status(
        settings: Settings,
        research_id: str,
        receipt: EvidenceDispatchReceipt,
    ) -> None:
        evidence_status = "under_review" if receipt.status == "accepted" else "failed"
        evidence_source = f"qrh:evidence-dispatch-receipt:{receipt.result_hash}"
        with archive_connection(settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT research_id FROM research_status_projection WHERE research_id=?",
                (research_id,),
            ).fetchone()
            if row is None:
                raise IncrementalIntakeError("Archive status projection is missing after release")
            connection.execute(
                """
                UPDATE research_status_projection
                SET evidence_status=?,evidence_source_urn=?,updated_at=?
                WHERE research_id=?
                """,
                (evidence_status, evidence_source, utc_now(), research_id),
            )

    def _complete_parent(self, run_id: str, item: IntakeItemResult) -> None:
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                unfinished = connection.execute(
                    "SELECT count(*) FROM step_execution WHERE run_id=? AND status<>'succeeded'",
                    (run_id,),
                ).fetchone()[0]
                if unfinished:
                    raise IncrementalIntakeError("parent run cannot complete with unfinished local steps")
                connection.execute(
                    "UPDATE pipeline_run SET run_status='succeeded',release_status='released',finished_at=? WHERE run_id=?",
                    (utc_now(), run_id),
                )
                self._insert_platform_event(
                    connection,
                    "ArchiveImportCompleted",
                    f"qrh:run:{run_id}",
                    {"run_urn": f"qrh:run:{run_id}", "item": item.to_dict()},
                )
        finally:
            connection.close()

    def _neutral_alias_target(
        self, source_sha256: str, *, current_neutral_slug: str
    ) -> dict[str, Any] | None:
        """返回唯一、可证明由中性 intake 创建的同内容文档。

        内容相同只足以登记新的来源 observation，不足以制造第二个 research。
        若历史库里同一内容已经落到多个中性文档，自动选择会掩盖旧冲突，故拒绝。
        """

        try:
            with archive_connection(self.settings) as archive:
                candidates = archive.execute(
                    """
                    SELECT DISTINCT research.research_id,research.canonical_slug,
                           document.document_id,version.document_version_id,
                           active.research_release_id,active.revision
                    FROM research_document_version AS version
                    JOIN research_document AS document USING(document_id)
                    JOIN research USING(research_id)
                    JOIN active_research_release AS active USING(research_id)
                    WHERE version.content_sha256=?
                      AND research.canonical_slug LIKE 'intake-%'
                    ORDER BY research.research_id,document.document_id
                    """,
                    (source_sha256,),
                ).fetchall()
                verified: list[dict[str, Any]] = []
                store = ObjectStore(self.settings.object_root)
                for candidate in candidates:
                    origins = archive.execute(
                        """
                        SELECT mapping_evidence_json
                        FROM research_document_origin
                        WHERE document_id=? AND mapping_status='verified'
                        ORDER BY first_seen_at,origin_id
                        """,
                        (candidate["document_id"],),
                    ).fetchall()
                    neutral_authority = False
                    for origin in origins:
                        try:
                            evidence = json.loads(str(origin["mapping_evidence_json"]))
                            authority_urn = str(evidence["authority_urn"])
                            if not authority_urn.startswith("qrh:object:"):
                                continue
                            authority_bytes = store.read_bytes(
                                authority_urn[len("qrh:object:") :]
                            )
                            authority = json.loads(authority_bytes.decode("utf-8"))
                        except (KeyError, TypeError, ValueError, UnicodeDecodeError):
                            continue
                        if (
                            authority_bytes.decode("utf-8") == canonical_json(authority)
                            and authority.get("schema_version")
                            == "qrh-neutral-one-document-mapping/v1"
                            and authority.get("policy_version")
                            == NEUTRAL_MAPPING_POLICY_VERSION
                            and authority.get("proposal", {}).get("research_slug")
                            == candidate["canonical_slug"]
                        ):
                            neutral_authority = True
                            break
                    if neutral_authority:
                        verified.append(dict(candidate))
                by_document = {str(row["document_id"]): row for row in verified}
        except Exception as error:
            if "no such table" in str(error):
                return None
            raise
        if not by_document:
            return None
        if len(by_document) != 1:
            raise IncrementalIntakeError(
                "same content is already bound to multiple neutral documents; alias is ambiguous"
            )
        target = next(iter(by_document.values()))
        # 当前路径自己的 normal publication 可能已在 dispatch 前中断；它应继续原
        # parent，而不是要求一个尚不存在的完成凭据，也不是来源 alias。
        if str(target["canonical_slug"]) == current_neutral_slug:
            return target

        platform = connect_database(self.settings.database_path)
        try:
            matches: list[IntakeItemResult] = []
            for event in platform.execute(
                """
                SELECT payload_json,payload_hash,event_version
                FROM outbox_event
                WHERE event_type='ArchiveImportCompleted'
                ORDER BY created_at,event_id
                """
            ):
                payload_json = str(event["payload_json"])
                if (
                    event["event_version"] != "1"
                    or event["payload_hash"]
                    != stable_sha256("integration-outbox/v1", payload_json)
                ):
                    raise IncrementalIntakeError(
                        "cannot resolve content alias through an invalid completion event"
                    )
                payload = json.loads(payload_json)
                if payload_json != canonical_json(payload):
                    raise IncrementalIntakeError(
                        "cannot resolve content alias through a noncanonical completion event"
                    )
                try:
                    item = IntakeItemResult(**dict(payload["item"]))
                except (KeyError, TypeError, ValueError) as error:
                    raise IncrementalIntakeError(
                        "cannot resolve content alias through an invalid completion item"
                    ) from error
                if (
                    item.state == "published"
                    and item.research_id == target["research_id"]
                    and item.document_version_id == target["document_version_id"]
                    and item.source_sha256 == source_sha256
                ):
                    matches.append(item)
        finally:
            platform.close()
        if len(matches) != 1:
            raise IncrementalIntakeError(
                "same-content neutral document lacks one canonical publication receipt"
            )
        target["canonical_item"] = matches[0]
        return target

    def _process_alias(
        self,
        *,
        source: IntakeSource,
        relative_path: str,
        source_bytes: bytes,
        source_digest: str,
        registration: Any,
        source_settings: Settings,
        source_path: str,
        source_key: str,
        run_id: str,
        parent_created: bool,
        target: dict[str, Any],
    ) -> IntakeItemResult:
        canonical: IntakeItemResult = target["canonical_item"]
        current_step = "build_neutral_mapping"
        try:
            mapping_payload = {
                "schema_version": "qrh-neutral-source-alias/v1",
                "policy_version": NEUTRAL_MAPPING_POLICY_VERSION,
                "source": {
                    "namespace": source.namespace,
                    "relative_path": relative_path,
                    "canonical_source_key": source_key,
                    "source_view_path": source_path,
                    "source_location_urn": f"qrh:source:{registration.source_location_id}",
                    "object_urn": f"qrh:object:{registration.object_id}",
                    "sha256": source_digest,
                    "bytes": len(source_bytes),
                },
                "alias_target": {
                    "research_id": str(target["research_id"]),
                    "research_slug": str(target["canonical_slug"]),
                    "document_id": str(target["document_id"]),
                    "document_version_id": str(target["document_version_id"]),
                    "canonical_parent_run_urn": f"qrh:run:{canonical.parent_run_id}",
                },
                "semantic_non_assertions": {
                    "new_research_inferred": False,
                    "new_document_version_inferred": False,
                    "summary_generated": False,
                    "completion_inferred": False,
                },
            }
            self._begin_step(run_id, current_step)
            mapping_urn, mapping_hash = self._store_json(
                mapping_payload,
                "application/vnd.qrh.source-alias+json; charset=utf-8",
            )
            self._finish_step(run_id, current_step, mapping_hash)

            current_step = "project_markdown"
            self._begin_step(run_id, current_step)
            projection = project_markdown(source_bytes)
            projection_hash = stable_sha256(
                "incremental-projection/v1",
                projection.projector_version,
                projection.document_sha256,
                str(len(projection.headings)),
                str(len(projection.math_nodes)),
                sha256_hex(projection.rendered_html.encode("utf-8")),
            )
            self._finish_step(run_id, current_step, projection_hash)

            current_step = "extract_clues"
            self._begin_step(run_id, current_step)
            clue_artifact = extract_clues(
                source_bytes,
                source_path=f"{source.namespace}:///{relative_path}",
                source_object_urn=f"qrh:object:{registration.object_id}",
            )
            clue_urn, clue_hash = self._store_json(
                clue_artifact.to_dict(),
                "application/vnd.qrh.clue-occurrences+json; charset=utf-8",
            )
            self._finish_step(run_id, current_step, clue_hash)

            current_step = "publish_archive"
            self._begin_step(run_id, current_step)
            evidence_json = canonical_json(
                {
                    "schema_version": "archive-document-origin-alias/v1",
                    "source_path": f"{source.namespace}:///{relative_path}",
                    "authority_urn": mapping_urn,
                    "alias_of_document_version_id": str(target["document_version_id"]),
                    "note": "同内容新路径仅登记来源 observation；未创建新研究或正文版本。",
                }
            )
            origin_kind = "archive_path" if source.namespace == "archive" else "research_inbox"
            alias_event_payload = {
                "schema_version": "qrh-archive-source-alias-event/v1",
                "source_location_urn": f"qrh:source:{registration.source_location_id}",
                "research_id": str(target["research_id"]),
                "document_id": str(target["document_id"]),
                "document_version_id": str(target["document_version_id"]),
                "content_sha256": source_digest,
                "mapping_authority_urn": mapping_urn,
            }
            alias_event_json = canonical_json(alias_event_payload)
            with archive_connection(source_settings) as archive, immediate_transaction(archive):
                active = archive.execute(
                    """
                    SELECT research_release_id,revision
                    FROM active_research_release WHERE research_id=?
                    """,
                    (target["research_id"],),
                ).fetchone()
                version = archive.execute(
                    """
                    SELECT object_urn,content_sha256,bytes FROM research_document_version
                    WHERE document_version_id=? AND document_id=?
                    """,
                    (target["document_version_id"], target["document_id"]),
                ).fetchone()
                if active is None or version is None or (
                    version["object_urn"],
                    version["content_sha256"],
                    int(version["bytes"]),
                ) != (
                    f"qrh:object:{registration.object_id}",
                    source_digest,
                    len(source_bytes),
                ):
                    raise IncrementalIntakeError("content alias target changed before registration")
                existing = archive.execute(
                    """
                    SELECT mapping_status,mapping_evidence_json
                    FROM research_document_origin
                    WHERE document_id=? AND source_location_urn=?
                    """,
                    (
                        target["document_id"],
                        f"qrh:source:{registration.source_location_id}",
                    ),
                ).fetchone()
                if existing is None:
                    archive.execute(
                        """
                        INSERT INTO research_document_origin(
                            origin_id,document_id,source_location_urn,origin_kind,
                            mapping_status,mapping_evidence_json,first_seen_at
                        ) VALUES(?,?,?,?,?,?,?)
                        """,
                        (
                            new_public_id("origin"),
                            target["document_id"],
                            f"qrh:source:{registration.source_location_id}",
                            origin_kind,
                            "verified",
                            evidence_json,
                            utc_now(),
                        ),
                    )
                elif (
                    existing["mapping_status"] != "verified"
                    or existing["mapping_evidence_json"] != evidence_json
                ):
                    raise IncrementalIntakeError("content alias origin conflicts with prior mapping")
                archive.execute(
                    """
                    INSERT INTO outbox_event(
                        event_id,event_type,event_version,aggregate_urn,payload_json,
                        payload_hash,created_at,published_at,publish_attempt_count
                    ) VALUES(?,'ArchiveSourceAliasRegistered','1',?,?,?,?,NULL,0)
                    ON CONFLICT(event_type,aggregate_urn,payload_hash) DO NOTHING
                    """,
                    (
                        new_public_id("evt"),
                        f"qrh:archive-document:{target['document_id']}",
                        alias_event_json,
                        stable_sha256("archive-outbox/v1", alias_event_json),
                        utc_now(),
                    ),
                )
                active_release_id = str(active["research_release_id"])
                active_revision = int(active["revision"])
            publish_hash = stable_sha256(
                "archive-source-alias-registration/v1",
                mapping_hash,
                registration.source_location_id,
                str(target["document_id"]),
                str(target["document_version_id"]),
            )
            self._finish_step(run_id, current_step, publish_hash)

            current_step = "dispatch_evidence"
            self._begin_step(run_id, current_step)
            # 同一 document version 的 occurrence 已由 canonical command 接收；别名不重复写 ledger。
            no_op_hash = stable_sha256(
                "evidence-source-alias-noop/v1",
                canonical.evidence_receipt_hash,
                registration.source_location_id,
                clue_hash,
            )
            self._finish_step(run_id, current_step, no_op_hash)

            item = IntakeItemResult(
                namespace=source.namespace,
                relative_path=relative_path,
                source_sha256=source_digest,
                source_bytes=len(source_bytes),
                parent_run_id=run_id,
                parent_created=parent_created,
                research_id=str(target["research_id"]),
                research_slug=str(target["canonical_slug"]),
                research_release_id=active_release_id,
                release_revision=active_revision,
                document_version_id=str(target["document_version_id"]),
                clue_artifact_urn=clue_urn,
                clue_count=len(clue_artifact.occurrences),
                evidence_child_run_urn=canonical.evidence_child_run_urn,
                evidence_dispatch_status=canonical.evidence_dispatch_status,
                evidence_receipt_hash=canonical.evidence_receipt_hash,
                state="aliased",
            )
            self._complete_parent(run_id, item)
            return item
        except Exception as error:
            self._fail_parent(run_id, current_step, error)
            raise

    def _process_one(
        self,
        source: IntakeSource,
        relative_path: str,
    ) -> IntakeItemResult:
        source_settings, source_path, source_bytes, source_digest = self._materialize_source(
            source, relative_path
        )
        registration = ingest_archive_snapshot(source_settings, source_path)
        initialize_archive_database(source_settings)
        source_key = self._source_key(source.namespace, relative_path)
        neutral_slug = f"intake-{stable_sha256(source_key)[:32]}"
        if not self._parent_exists(source_key=source_key, source_sha256=source_digest):
            mappings = self._verified_origin_mappings(
                source_settings, registration.source_location_id
            )
            mapped_slugs = {str(row["research_slug"]) for row in mappings}
            exact_urn = f"qrh:source:{registration.source_location_id}"
            with archive_connection(source_settings) as connection:
                exact_count = int(
                    connection.execute(
                        """
                        SELECT count(*) FROM research_document_origin
                        WHERE source_location_urn=? AND mapping_status='verified'
                        """,
                        (exact_urn,),
                    ).fetchone()[0]
                )
            if exact_count:
                raise _IntakeSkipped("该稳定快照已由显式 Archive 映射接管。")
            if mapped_slugs and mapped_slugs != {neutral_slug}:
                raise _IntakeSkipped(
                    "同一来源已有非中性研究映射；为避免错误覆盖，需由现有 release manifest 接续。"
                )
        run_id, parent_created, _ = self._ensure_parent_run(
            registration=registration,
            source_key=source_key,
            source_sha256=source_digest,
        )
        completed = self._completed_result(
            run_id,
            registration=registration,
            namespace=source.namespace,
            relative_path=relative_path,
            source_key=source_key,
            source_sha256=source_digest,
            source_payload=source_bytes,
        )
        if completed is not None:
            if completed.source_sha256 != source_digest:
                raise IncrementalIntakeError("completion receipt is bound to different source bytes")
            return completed

        alias_target = self._neutral_alias_target(
            source_digest, current_neutral_slug=neutral_slug
        )
        if (
            alias_target is not None
            and str(alias_target["canonical_slug"]) != neutral_slug
        ):
            return self._process_alias(
                source=source,
                relative_path=relative_path,
                source_bytes=source_bytes,
                source_digest=source_digest,
                registration=registration,
                source_settings=source_settings,
                source_path=source_path,
                source_key=source_key,
                run_id=run_id,
                parent_created=parent_created,
                target=alias_target,
            )

        current_step = "build_neutral_mapping"
        try:
            research_slug = neutral_slug
            display_path = relative_path if len(relative_path) <= 240 else f"…{relative_path[-239:]}"
            display_title = f"自动导入研究 · {display_path}"
            release_key = f"auto-{source_digest[:20]}"
            mapping_payload = {
                "schema_version": "qrh-neutral-one-document-mapping/v1",
                "policy_version": NEUTRAL_MAPPING_POLICY_VERSION,
                "source": {
                    "namespace": source.namespace,
                    "relative_path": relative_path,
                    "canonical_source_key": source_key,
                    "source_view_path": source_path,
                    "object_urn": f"qrh:object:{registration.object_id}",
                    "sha256": source_digest,
                    "bytes": len(source_bytes),
                },
                "proposal": {
                    "research_slug": research_slug,
                    "document_slug": "main",
                    "document_role": "primary",
                    "display_title_kind": "source_path_label",
                },
                "semantic_non_assertions": {
                    "completion_inferred": False,
                    "summary_generated": False,
                    "topic_inferred": False,
                    "paper_identity_inferred": False,
                },
            }
            self._begin_step(run_id, current_step)
            mapping_urn, mapping_hash = self._store_json(
                mapping_payload,
                "application/vnd.qrh.neutral-mapping+json; charset=utf-8",
            )
            self._finish_step(run_id, current_step, mapping_hash)

            current_step = "project_markdown"
            self._begin_step(run_id, current_step)
            projection = project_markdown(source_bytes)
            projection_hash = stable_sha256(
                "incremental-projection/v1",
                projection.projector_version,
                projection.document_sha256,
                str(len(projection.headings)),
                str(len(projection.math_nodes)),
                sha256_hex(projection.rendered_html.encode("utf-8")),
            )
            self._finish_step(run_id, current_step, projection_hash)

            current_step = "extract_clues"
            self._begin_step(run_id, current_step)
            clue_artifact: ClueArtifact = extract_clues(
                source_bytes,
                source_path=f"{source.namespace}:///{relative_path}",
                source_object_urn=f"qrh:object:{registration.object_id}",
            )
            clue_urn, clue_hash = self._store_json(
                clue_artifact.to_dict(),
                "application/vnd.qrh.clue-occurrences+json; charset=utf-8",
            )
            self._finish_step(run_id, current_step, clue_hash)

            connection = connect_database(self.settings.database_path)
            try:
                source_row = connection.execute(
                    "SELECT origin_uri FROM source_location WHERE source_location_id=?",
                    (registration.source_location_id,),
                ).fetchone()
            finally:
                connection.close()
            if source_row is None:
                raise IncrementalIntakeError("source registry row disappeared")
            previous = self._previous_content(source_settings, research_slug)
            relations: tuple[ArchiveVersionRelationInput, ...] = ()
            if previous is not None and previous != source_digest:
                relations = (
                    ArchiveVersionRelationInput(
                        document_slug="main",
                        from_content_sha256=previous,
                        to_content_sha256=source_digest,
                        relation_kind="supersedes",
                        status="verified",
                        provenance_urn=mapping_urn,
                    ),
                )
            draft = ArchiveReleaseInput(
                research_slug=research_slug,
                display_title=display_title,
                release_key=release_key,
                documents=(
                    ArchiveDocumentInput(
                        document_slug="main",
                        document_role="primary",
                        source_path=source_path,
                        approved_origin_uri=str(source_row["origin_uri"]),
                        approved_object_urn=f"qrh:object:{registration.object_id}",
                        approved_content_sha256=source_digest,
                        approved_bytes=len(source_bytes),
                        navigation_role="primary",
                        sort_key=10,
                        mapping_authority_urn=mapping_urn,
                        mapping_note=(
                            "按已审核中性单文档策略映射；只确认稳定来源身份，不推断摘要、"
                            "topic、完成状态或论文事实。"
                        ),
                    ),
                ),
                version_relations=relations,
                activate=False,
            )

            current_step = "publish_archive"
            self._begin_step(run_id, current_step)
            catalog = ArchiveCatalog(source_settings)
            candidate_spec = catalog.prepare_release_candidate(draft)
            gate_payload = {
                "schema_version": "qrh-incremental-archive-gate/v1",
                "policy_version": NEUTRAL_MAPPING_POLICY_VERSION,
                "candidate": {
                    "artifact_manifest_hash": candidate_spec.artifact_manifest_hash,
                    "source_snapshot_hash": candidate_spec.source_snapshot_hash,
                    "projection_revision": candidate_spec.projection_revision,
                },
                "checks": {
                    "stable_source_bytes": source_digest == sha256_hex(source_bytes),
                    "utf8_projection": projection.document_sha256 == source_digest,
                    "one_primary_document": True,
                    "no_generated_summary": draft.summary is None,
                    "no_completion_decision": True,
                    "clue_spans_exact": all(
                        source_bytes[item.byte_start : item.byte_end]
                        == item.raw_marker_text.encode("utf-8")
                        for item in clue_artifact.occurrences
                    ),
                },
            }
            if not all(gate_payload["checks"].values()):
                raise IncrementalIntakeError("incremental Archive deterministic gate failed")
            gate_hash = sha256_hex(canonical_json(gate_payload).encode("utf-8"))
            authority = ReleaseAuthority(self.settings)
            candidate = authority.register_candidate(candidate_spec)
            decision = authority.record_decision(
                candidate.candidate_id,
                deterministic_gate_hash=gate_hash,
                review_set_hash=stable_sha256(
                    "incremental-intake-policy-review/v1",
                    NEUTRAL_MAPPING_POLICY_VERSION,
                    "project-design-4.2",
                    "no-semantic-completion",
                ),
                reconciliation_hash=stable_sha256(
                    "incremental-intake-reconciliation/v1",
                    mapping_hash,
                    clue_hash,
                    candidate_spec.artifact_manifest_hash,
                ),
                verdict="pass",
            )
            certificate = authority.issue_snapshot(
                decision.decision_id,
                requirements_manifest_hash=candidate_spec.requirements_manifest_hash,
                issuance_key=stable_sha256(
                    "incremental-intake-issuance/v1", run_id, candidate_spec.artifact_manifest_hash
                ),
            )
            approved = draft.model_copy(
                update={
                    "activate": True,
                    "release_snapshot_urn": certificate.snapshot_urn,
                    "activation_decision_hash": certificate.decision_hash,
                }
            )
            published = catalog.publish_release(approved)
            page = catalog.research_page(published.research_id)
            if (
                len(page["documents"]) != 1
                or page["documents"][0]["content_sha256"] != source_digest
                or published.active_revision is None
            ):
                raise IncrementalIntakeError("published Archive page failed exact-byte verification")
            self._finish_step(
                run_id,
                current_step,
                stable_sha256(
                    "incremental-archive-publication/v1",
                    published.research_id,
                    published.research_release_id,
                    certificate.snapshot_urn,
                    str(published.active_revision),
                ),
            )

            current_step = "dispatch_evidence"
            self._begin_step(run_id, current_step)
            document_version_id = published.document_version_ids[0]
            archive_event_id, _ = self._archive_document_event(
                source_settings, document_version_id
            )
            evidence_input_hash = stable_sha256(
                "evidence-ingest-child-input/v1",
                candidate_spec.subject_urn,
                published.research_release_id,
                document_version_id,
                clue_hash,
            )
            dispatch_key = stable_sha256(
                "evidence-ingest-command/v1", archive_event_id, evidence_input_hash
            )
            child_run_id, _ = self._ensure_child_run(
                idempotency_key=dispatch_key,
                subject_urn=candidate_spec.subject_urn,
                input_hash=evidence_input_hash,
            )
            occurrence_rows = tuple(
                {
                    **item.to_dict(),
                    "legacy_occurrence_id": f"auto_{item.citation_id}",
                    "research_urn": candidate_spec.subject_urn,
                    "archive_release_urn": f"qrh:archive-release:{research_slug}:{release_key}",
                    "document_version_urn": f"qrh:archive-document-version:{registration.object_id}",
                    "source_object_urn": f"qrh:object:{registration.object_id}",
                    "source_path": f"{source.namespace}:///{relative_path}",
                    "locator_kind": "utf8_bytes",
                    "locator": {
                        "line": item.line_start,
                        "byte_start": item.byte_start,
                        "byte_end": item.byte_end,
                    },
                }
                for item in clue_artifact.occurrences
            )
            command = EvidenceIngestCommand(
                schema_version="qrh-evidence-ingest-command/v1",
                idempotency_key=dispatch_key,
                child_run_urn=f"qrh:run:{child_run_id}",
                parent_run_urn=f"qrh:run:{run_id}",
                archive_event_id=archive_event_id,
                research_urn=candidate_spec.subject_urn,
                archive_release_urn=f"qrh:archive-release:{research_slug}:{release_key}",
                document_version_urn=f"qrh:archive-document-version:{registration.object_id}",
                source_object_urn=f"qrh:object:{registration.object_id}",
                source_path=f"{source.namespace}:///{relative_path}",
                clue_artifact_urn=clue_urn,
                clue_artifact_sha256=clue_hash,
                occurrences=occurrence_rows,
            )
            try:
                receipt = self.evidence_adapter.dispatch(command)
            except Exception as error:
                raise IncrementalIntakeError(
                    "Evidence adapter failed before returning a verifiable receipt: "
                    f"{type(error).__name__}: {error}"
                ) from error
            receipt.verify(command)
            self._record_child_receipt(child_run_id, receipt)
            if receipt.status == "accepted":
                self._acknowledge_evidence_result(
                    source_settings,
                    adapter=self.evidence_adapter,
                    command=command,
                    receipt=receipt,
                )
                self._mark_archive_event_delivered(
                    source_settings,
                    event_id=archive_event_id,
                    document_version_id=document_version_id,
                    receipt=receipt,
                )
            self._project_dispatch_status(source_settings, published.research_id, receipt)
            if receipt.status == "blocked_external":
                self._block_parent(run_id, current_step, receipt)
                raise _IntakeWaitingExternal(receipt.detail)
            if receipt.status != "accepted":
                raise IncrementalIntakeError(
                    f"Evidence target rejected the command: {receipt.detail}"
                )
            self._finish_step(run_id, current_step, receipt.result_hash)

            item = IntakeItemResult(
                namespace=source.namespace,
                relative_path=relative_path,
                source_sha256=source_digest,
                source_bytes=len(source_bytes),
                parent_run_id=run_id,
                parent_created=parent_created,
                research_id=published.research_id,
                research_slug=research_slug,
                research_release_id=published.research_release_id,
                release_revision=int(published.active_revision),
                document_version_id=document_version_id,
                clue_artifact_urn=clue_urn,
                clue_count=len(clue_artifact.occurrences),
                evidence_child_run_urn=command.child_run_urn,
                evidence_dispatch_status=receipt.status,
                evidence_receipt_hash=receipt.result_hash,
                state="published",
            )
            self._complete_parent(run_id, item)
            return item
        except _IntakeWaitingExternal:
            raise
        except Exception as error:
            self._fail_parent(run_id, current_step, error)
            raise

    def scan(self, sources: tuple[IntakeSource, ...]) -> IntakeReport:
        started_at = utc_now()
        initialize_platform(self.settings)
        processed: list[IntakeItemResult] = []
        skipped: list[IntakeSkip] = []
        issues: list[IntakeIssue] = []
        for source in sources:
            try:
                paths, discovery_issues = _enumerate_markdown(source.root)
                issues.extend(
                    replace(issue, namespace=source.namespace) for issue in discovery_issues
                )
            except Exception as error:
                issues.append(
                    IntakeIssue(
                        source.namespace,
                        ".",
                        "source_root_rejected",
                        type(error).__name__,
                        str(error),
                    )
                )
                continue
            for relative_path in paths:
                source_before = (source.root / Path(relative_path)).read_bytes()
                try:
                    result = self._process_one(source, relative_path)
                    processed.append(result)
                except _IntakeSkipped as skip:
                    skipped.append(
                        IntakeSkip(source.namespace, relative_path, skip.reason)
                    )
                except _IntakeWaitingExternal as waiting:
                    issues.append(
                        IntakeIssue(
                            source.namespace,
                            relative_path,
                            "evidence_waiting_external",
                            "ExternalEvidencePending",
                            waiting.detail,
                        )
                    )
                except Exception as error:
                    issues.append(
                        IntakeIssue(
                            source.namespace,
                            relative_path,
                            "intake_failed",
                            type(error).__name__,
                            str(error),
                        )
                    )
                finally:
                    try:
                        source_after = (source.root / Path(relative_path)).read_bytes()
                        if source_after != source_before:
                            issues.append(
                                IntakeIssue(
                                    source.namespace,
                                    relative_path,
                                    "source_bytes_changed",
                                    "SourceIntegrityError",
                                    "增量编排前后来源字节不同。",
                                )
                            )
                    except OSError as error:
                        issues.append(
                            IntakeIssue(
                                source.namespace,
                                relative_path,
                                "source_recheck_failed",
                                type(error).__name__,
                                str(error),
                            )
                        )
        processed.sort(key=lambda item: (item.namespace, item.relative_path.casefold(), item.relative_path))
        skipped.sort(key=lambda item: (item.namespace, item.relative_path.casefold(), item.relative_path))
        issues.sort(key=lambda item: (item.namespace, item.relative_path.casefold(), item.code))
        if issues and not processed:
            status: Literal["PASS", "PARTIAL", "ERROR"] = "ERROR"
        elif issues:
            status = "PARTIAL"
        else:
            status = "PASS"
        return IntakeReport(
            schema_version="qrh-incremental-intake-report/v1",
            status=status,
            started_at=started_at,
            completed_at=utc_now(),
            processed=tuple(processed),
            skipped=tuple(skipped),
            issues=tuple(issues),
        )
