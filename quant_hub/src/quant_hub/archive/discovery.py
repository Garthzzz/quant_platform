from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import stat
from typing import Literal

from quant_hub.config import Settings, stat_is_reparse_point
from quant_hub.platform.db import connect_database, utc_now

from .database import archive_connection, initialize_archive_database
from .service import ingest_archive_snapshot, initialize_platform
from .source_reader import ReadOnlyArchiveSource, SourceBoundaryError


DISCOVERY_SCHEMA_VERSION = "archive-discovery-report/v1"
MAPPING_POLICY = "explicit_verified_manifest_required"

ObservationState = Literal["discovered", "changed", "unchanged"]
MappingState = Literal["mapped", "unmapped"]
WorkflowState = Literal["mapped", "pending_mapping"]


@dataclass(frozen=True, slots=True)
class ArchiveMappingRecord:
    research_id: str
    research_slug: str
    document_id: str
    document_slug: str
    mapping_status: str


@dataclass(frozen=True, slots=True)
class ArchiveDiscoveryItem:
    relative_path: str
    origin_uri: str
    sha256: str
    bytes: int
    object_id: str
    source_location_id: str
    run_id: str
    run_created: bool
    observation_state: ObservationState
    mapping_state: MappingState
    workflow_state: WorkflowState
    mappings: tuple[ArchiveMappingRecord, ...]


@dataclass(frozen=True, slots=True)
class ArchiveDiscoveryIssue:
    relative_path: str
    issue_code: str
    error_type: str
    detail: str


@dataclass(frozen=True, slots=True)
class ArchiveDiscoveryCounts:
    markdown_candidates: int
    processed: int
    discovered: int
    changed: int
    unchanged: int
    mapped: int
    unmapped: int
    pending_mapping: int
    errors: int


@dataclass(frozen=True, slots=True)
class ArchiveDiscoveryReport:
    schema_version: str
    status: Literal["PASS", "PARTIAL", "ERROR"]
    started_at: str
    completed_at: str
    archive_root: str
    mapping_policy: str
    counts: ArchiveDiscoveryCounts
    items: tuple[ArchiveDiscoveryItem, ...]
    issues: tuple[ArchiveDiscoveryIssue, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _safe_relative(path: Path, root: Path) -> str:
    """只用于错误报告；不能把该结果当成已验证的 Archive 身份。"""

    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return "<outside-archive-root>"


def _enumerate_markdown(root: Path) -> tuple[list[str], list[ArchiveDiscoveryIssue]]:
    """枚举真实目录中的 Markdown，不跟随 symlink/junction/reparse。

    文件的最终边界、规范路径、普通文件类型和稳定性仍由
    :class:`ReadOnlyArchiveSource` 在快照时再次验证。这里的检查负责阻止递归
    穿过 reparse，并把被拒绝的入口写进可审计报告，而不是静默跳过。
    """

    candidates: list[str] = []
    issues: list[ArchiveDiscoveryIssue] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        relative_directory = _safe_relative(directory, root) or "."
        try:
            directory_info = directory.lstat()
            if stat_is_reparse_point(directory_info):
                raise SourceBoundaryError("Archive enumeration rejected a reparse directory")
            if not stat.S_ISDIR(directory_info.st_mode):
                raise SourceBoundaryError("Archive enumeration path is not a directory")
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: (entry.name.casefold(), entry.name))
        except (OSError, SourceBoundaryError) as error:
            issues.append(
                ArchiveDiscoveryIssue(
                    relative_path=relative_directory,
                    issue_code="directory_boundary_rejected",
                    error_type=type(error).__name__,
                    detail=str(error),
                )
            )
            continue

        child_directories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            relative = _safe_relative(path, root)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                issues.append(
                    ArchiveDiscoveryIssue(
                        relative_path=relative,
                        issue_code="entry_stat_failed",
                        error_type=type(error).__name__,
                        detail=str(error),
                    )
                )
                continue
            if stat_is_reparse_point(info):
                # 目录 reparse 可能越界；Markdown 文件 reparse 同样不能作为来源。
                if stat.S_ISDIR(info.st_mode) or path.suffix.lower() in {".md", ".markdown"}:
                    issues.append(
                        ArchiveDiscoveryIssue(
                            relative_path=relative,
                            issue_code="reparse_rejected",
                            error_type="SourceBoundaryError",
                            detail="Archive discovery does not follow reparse entries",
                        )
                    )
                continue
            if stat.S_ISDIR(info.st_mode):
                child_directories.append(path)
                continue
            if path.suffix.lower() not in {".md", ".markdown"}:
                continue
            if not stat.S_ISREG(info.st_mode):
                issues.append(
                    ArchiveDiscoveryIssue(
                        relative_path=relative,
                        issue_code="non_regular_markdown_rejected",
                        error_type="SourceBoundaryError",
                        detail="Archive Markdown source must be a regular file",
                    )
                )
                continue
            candidates.append(relative)
        # LIFO 栈逆序入栈，使实际处理顺序仍可由最终全局排序完全决定。
        pending.extend(reversed(child_directories))

    return sorted(set(candidates), key=lambda value: (value.casefold(), value)), sorted(
        issues,
        key=lambda issue: (issue.relative_path.casefold(), issue.relative_path, issue.issue_code),
    )


class ArchiveDiscoveryScanner:
    """Archive 增量发现服务。

    该服务只完成安全发现、A1 不可变快照登记和显式映射查询。它不会根据目录、
    文件名或正文猜测 research/document/version 关系，也不会创建 release 或切换
    active pointer。没有精确命中 ``verified`` source-location 映射的快照只能进入
    ``pending_mapping``。

    ``observation_state`` 表示当前 origin/content 对是否已被 source registry 见过：
    新 origin 为 ``discovered``；已知 origin 的新 content object 为 ``changed``；
    已登记的同一不可变快照为 ``unchanged``。因此回到历史上已登记的相同字节仍是
    ``unchanged``，这有意描述 registry 新颖性，而不是伪造一个不存在的可变
    “最新文件”指针。
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    @staticmethod
    def _observation_state(
        connection,
        *,
        origin_uri: str,
        object_id: str,
        run_created: bool,
    ) -> ObservationState:
        rows = connection.execute(
            """
            SELECT object_id
            FROM source_location
            WHERE namespace='archive' AND origin_uri=?
            """,
            (origin_uri,),
        ).fetchall()
        if not rows or all(row["object_id"] != object_id for row in rows):
            raise RuntimeError("registered Archive snapshot is missing from source registry")
        if not run_created:
            return "unchanged"
        return "discovered" if len(rows) == 1 else "changed"

    @staticmethod
    def _mappings(connection, source_location_id: str) -> tuple[ArchiveMappingRecord, ...]:
        source_urn = f"qrh:source:{source_location_id}"
        rows = connection.execute(
            """
            SELECT research.research_id,
                   research.canonical_slug AS research_slug,
                   document.document_id,
                   document.slug AS document_slug,
                   origin.mapping_status
            FROM research_document_origin AS origin
            JOIN research_document AS document USING(document_id)
            JOIN research USING(research_id)
            WHERE origin.source_location_urn=?
            ORDER BY research.canonical_slug,document.slug,origin.origin_id
            """,
            (source_urn,),
        ).fetchall()
        return tuple(
            ArchiveMappingRecord(
                research_id=str(row["research_id"]),
                research_slug=str(row["research_slug"]),
                document_id=str(row["document_id"]),
                document_slug=str(row["document_slug"]),
                mapping_status=str(row["mapping_status"]),
            )
            for row in rows
        )

    def scan(self) -> ArchiveDiscoveryReport:
        started_at = utc_now()
        # 构造 reader 会先验证 Archive root 及其全部已有祖先均非 reparse。
        reader = ReadOnlyArchiveSource(self.settings.archive_root)
        initialize_platform(self.settings)
        initialize_archive_database(self.settings)
        candidates, issues = _enumerate_markdown(reader.root)
        items: list[ArchiveDiscoveryItem] = []

        platform = connect_database(self.settings.database_path)
        try:
            with archive_connection(self.settings) as archive:
                for relative_path in candidates:
                    try:
                        registration = ingest_archive_snapshot(self.settings, relative_path)
                        row = platform.execute(
                            """
                            SELECT origin_uri,observed_path,object_id
                            FROM source_location WHERE source_location_id=?
                            """,
                            (registration.source_location_id,),
                        ).fetchone()
                        if row is None or (
                            row["observed_path"] != relative_path
                            or row["object_id"] != registration.object_id
                        ):
                            raise RuntimeError("source registry returned an incompatible identity")
                        mappings = self._mappings(archive, registration.source_location_id)
                        mapping_state: MappingState = (
                            "mapped"
                            if any(mapping.mapping_status == "verified" for mapping in mappings)
                            else "unmapped"
                        )
                        items.append(
                            ArchiveDiscoveryItem(
                                relative_path=relative_path,
                                origin_uri=str(row["origin_uri"]),
                                sha256=registration.object_id.removeprefix("obj_sha256_"),
                                bytes=int(
                                    platform.execute(
                                        "SELECT bytes FROM object_blob WHERE object_id=?",
                                        (registration.object_id,),
                                    ).fetchone()[0]
                                ),
                                object_id=registration.object_id,
                                source_location_id=registration.source_location_id,
                                run_id=registration.run_id,
                                run_created=registration.run_created,
                                observation_state=self._observation_state(
                                    platform,
                                    origin_uri=str(row["origin_uri"]),
                                    object_id=registration.object_id,
                                    run_created=registration.run_created,
                                ),
                                mapping_state=mapping_state,
                                workflow_state=(
                                    "mapped" if mapping_state == "mapped" else "pending_mapping"
                                ),
                                mappings=mappings,
                            )
                        )
                    except Exception as error:
                        issues.append(
                            ArchiveDiscoveryIssue(
                                relative_path=relative_path,
                                issue_code=(
                                    "source_boundary_rejected"
                                    if isinstance(error, SourceBoundaryError)
                                    else "snapshot_registration_failed"
                                ),
                                error_type=type(error).__name__,
                                detail=str(error),
                            )
                        )
        finally:
            platform.close()

        items.sort(key=lambda item: (item.relative_path.casefold(), item.relative_path))
        issues.sort(
            key=lambda issue: (issue.relative_path.casefold(), issue.relative_path, issue.issue_code)
        )
        counts = ArchiveDiscoveryCounts(
            markdown_candidates=len(candidates),
            processed=len(items),
            discovered=sum(item.observation_state == "discovered" for item in items),
            changed=sum(item.observation_state == "changed" for item in items),
            unchanged=sum(item.observation_state == "unchanged" for item in items),
            mapped=sum(item.mapping_state == "mapped" for item in items),
            unmapped=sum(item.mapping_state == "unmapped" for item in items),
            pending_mapping=sum(item.workflow_state == "pending_mapping" for item in items),
            errors=len(issues),
        )
        if issues and not items:
            status: Literal["PASS", "PARTIAL", "ERROR"] = "ERROR"
        elif issues:
            status = "PARTIAL"
        else:
            status = "PASS"
        return ArchiveDiscoveryReport(
            schema_version=DISCOVERY_SCHEMA_VERSION,
            status=status,
            started_at=started_at,
            completed_at=utc_now(),
            archive_root=str(reader.root),
            mapping_policy=MAPPING_POLICY,
            counts=counts,
            items=tuple(items),
            issues=tuple(issues),
        )
