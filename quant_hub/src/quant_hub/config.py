from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat


class ConfigurationError(ValueError):
    pass


def stat_is_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def is_reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat_is_reparse_point(info)


def ensure_no_reparse_components(path: Path) -> None:
    absolute = path.absolute()
    chain: list[Path] = []
    current = absolute
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if os.path.lexists(candidate) and is_reparse_point(candidate):
            raise ConfigurationError(f"path contains a reparse component: {candidate}")


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class Settings:
    project_root: Path
    archive_root: Path
    var_root: Path
    database_path: Path
    object_root: Path
    migration_root: Path
    read_only_runtime: bool = False

    @property
    def archive_database_path(self) -> Path:
        """Archive 业务库；与 platform.sqlite3 保持物理隔离。"""

        return self.var_root / "db" / "archive.sqlite3"

    @property
    def archive_migration_root(self) -> Path:
        return self.migration_root.parent / "archive"

    @property
    def research_papers_database_path(self) -> Path:
        """Archive Evidence 业务库；不得与 Paper Lab 或 Archive 共库。"""

        return self.var_root / "db" / "research_papers.sqlite3"

    @property
    def research_papers_root(self) -> Path:
        """合法获取的论文资源、manifest 与确定性导出根。"""

        return self.var_root / "research_papers"

    @property
    def research_papers_migration_root(self) -> Path:
        return self.migration_root.parent / "research_papers"

    @property
    def evidence_replay_root(self) -> Path:
        """Evidence 全量回放只能在此受管根创建隔离子树。"""

        return self.var_root / "replay" / "evidence"

    @property
    def paper_lab_database_path(self) -> Path:
        """迁移后的外部论文研究系统独立业务库。"""

        return self.var_root / "db" / "paper_lab.sqlite3"

    @property
    def paper_lab_asset_root(self) -> Path:
        return self.var_root / "paper_lab" / "assets"

    @property
    def paper_lab_migration_root(self) -> Path:
        return self.migration_root.parent / "paper_lab"

    @property
    def research_workspace_database_path(self) -> Path:
        """研究目录、状态、评论与历史的独立持久业务库。"""

        return self.var_root / "db" / "research_workspace.sqlite3"

    @property
    def research_workspace_migration_root(self) -> Path:
        return self.migration_root.parent / "research_workspace"

    @property
    def paper_lab_drop_root(self) -> Path:
        """保留 proj2 的 papers 投放习惯，但位于新系统可写区。"""

        return self.project_root / "quant_hub" / "paper_lab" / "papers"

    @property
    def research_workspace_root(self) -> Path:
        """研究管理树的可写 Markdown 来源；与只读 reference 严格隔离。"""

        return self.project_root / "研究修订工作区"

    @classmethod
    def default(
        cls,
        *,
        project_root: Path | None = None,
        archive_root: Path | None = None,
        var_root: Path | None = None,
        migration_root: Path | None = None,
        read_only_runtime: bool = False,
    ) -> "Settings":
        source_formal_root = Path(__file__).resolve().parents[2]
        source_migrations = source_formal_root / "migrations" / "platform"
        if source_migrations.is_dir():
            formal_root = source_formal_root
            workspace_root = formal_root.parent
            discovered_migration_root = source_migrations
            default_runtime = formal_root / "var"
        else:
            # Wheel/data-files 布局：package 位于 <install>/quant_hub，migration
            # 位于 <install>/migrations；运行数据必须落在用户项目而非 site-packages。
            install_root = Path(__file__).resolve().parents[1]
            discovered_migration_root = install_root / "migrations" / "platform"
            workspace_root = Path.cwd().resolve()
            default_runtime = workspace_root / "quant_hub" / "var"
        project = (project_root or workspace_root).resolve()
        archive = (archive_root or project / "reference" / "archive").absolute()
        runtime = (var_root or default_runtime).absolute()
        selected_migration_root = (
            migration_root or discovered_migration_root
        ).absolute()
        settings = cls(
            project_root=project,
            archive_root=archive,
            var_root=runtime,
            database_path=runtime / "db" / "platform.sqlite3",
            object_root=runtime / "objects",
            migration_root=selected_migration_root,
            read_only_runtime=read_only_runtime,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        ensure_no_reparse_components(self.archive_root)
        ensure_no_reparse_components(self.var_root)
        ensure_no_reparse_components(self.migration_root)
        ensure_no_reparse_components(self.paper_lab_drop_root)
        archive = self.archive_root.resolve(strict=True)
        if not archive.is_dir():
            raise ConfigurationError("archive root must be an existing directory")
        runtime = self.var_root.resolve(strict=False)
        project = self.project_root.resolve(strict=True)
        if not _is_relative_to(archive, project):
            raise ConfigurationError("archive root must stay inside the configured project")
        if not _is_relative_to(runtime, project):
            raise ConfigurationError("runtime must stay inside the configured project")
        if _is_relative_to(runtime, archive) or _is_relative_to(archive, runtime):
            raise ConfigurationError("runtime and read-only archive roots must not overlap")
        reference_root = (project / "reference").resolve(strict=True)
        if _is_relative_to(runtime, reference_root):
            raise ConfigurationError("runtime must not be placed inside reference/**")
        if self.database_path.parent != runtime / "db":
            raise ConfigurationError("database path must be rooted under var/db")
        if not _is_relative_to(self.object_root.resolve(strict=False), runtime):
            raise ConfigurationError("object root must be rooted under var")
        for managed in (
            self.research_papers_database_path,
            self.research_papers_root,
            self.evidence_replay_root,
            self.paper_lab_database_path,
            self.paper_lab_asset_root,
            self.research_workspace_database_path,
        ):
            if not _is_relative_to(managed.resolve(strict=False), runtime):
                raise ConfigurationError(f"managed path must stay under var: {managed}")
        drop_root = self.paper_lab_drop_root.resolve(strict=False)
        if not _is_relative_to(drop_root, project):
            raise ConfigurationError("Paper Lab drop root must stay inside the project")
        if _is_relative_to(drop_root, reference_root):
            raise ConfigurationError("Paper Lab drop root must not be inside reference/**")
        workspace_root = self.research_workspace_root.resolve(strict=False)
        if not _is_relative_to(workspace_root, project):
            raise ConfigurationError("research workspace root must stay inside the project")
        if _is_relative_to(workspace_root, reference_root):
            raise ConfigurationError("research workspace root must not be inside reference/**")
        if _is_relative_to(workspace_root, runtime) or _is_relative_to(runtime, workspace_root):
            raise ConfigurationError("research workspace and runtime roots must not overlap")
        migration_roots = {
            "platform": self.migration_root,
            "archive": self.archive_migration_root,
            "research_papers": self.research_papers_migration_root,
            "paper_lab": self.paper_lab_migration_root,
            "research_workspace": self.research_workspace_migration_root,
        }
        for domain, migration_root in migration_roots.items():
            ensure_no_reparse_components(migration_root)
            if not migration_root.is_dir():
                raise ConfigurationError(
                    f"{domain} migration directory is missing"
                )

    def validate_reviewed_runtime(self) -> None:
        """正式候选必须只消费自身冻结的全部业务域 migration 契约。"""

        self.validate()
        expected = (
            self.var_root / "runtime_contract" / "migrations" / "platform"
        ).resolve(strict=False)
        actual = self.migration_root.resolve(strict=True)
        if not expected.is_dir() or actual != expected:
            raise ConfigurationError(
                "reviewed runtime migration root must be sealed inside var_root"
            )

    def ensure_runtime_directories(self) -> None:
        # Check every existing ancestor before creating descendants so an
        # already-replaced runtime root cannot be followed even once.
        ensure_no_reparse_components(self.var_root)
        if self.read_only_runtime:
            if not self.var_root.is_dir():
                raise ConfigurationError("read-only runtime root must already exist")
            for directory in (
                self.database_path.parent,
                self.object_root,
                self.research_papers_root,
                self.evidence_replay_root,
                self.paper_lab_asset_root,
                self.paper_lab_drop_root,
                self.research_workspace_root,
            ):
                ensure_no_reparse_components(directory)
                if os.path.lexists(directory) and not directory.is_dir():
                    raise ConfigurationError(
                        f"read-only runtime path must be a directory: {directory}"
                    )
            return
        self.var_root.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(self.var_root)
        for directory in (
            self.database_path.parent,
            self.object_root,
            self.research_papers_root,
            self.evidence_replay_root,
            self.paper_lab_asset_root,
            self.paper_lab_drop_root,
            self.research_workspace_root,
        ):
            ensure_no_reparse_components(directory)
            directory.mkdir(parents=True, exist_ok=True)
            ensure_no_reparse_components(directory)
        for database_path in (
            self.database_path,
            self.archive_database_path,
            self.research_papers_database_path,
            self.paper_lab_database_path,
            self.research_workspace_database_path,
        ):
            try:
                database_info = database_path.lstat()
            except FileNotFoundError:
                continue
            if (
                stat_is_reparse_point(database_info)
                or not stat.S_ISREG(database_info.st_mode)
                or database_info.st_nlink != 1
            ):
                raise ConfigurationError(
                    "database path must be a regular, non-reparse, non-hard-linked file"
                )
