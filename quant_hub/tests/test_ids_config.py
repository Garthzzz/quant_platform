from __future__ import annotations

from pathlib import Path

from quant_hub.config import ConfigurationError, Settings
from quant_hub.ids import new_public_id, object_id_for_sha256, stable_sha256, validate_public_id
from tests.helpers import SettingsTestCase


class IdTests(SettingsTestCase):
    def test_public_and_content_ids_are_valid(self) -> None:
        value = new_public_id("run")
        self.assertEqual(value, validate_public_id(value))
        self.assertEqual("obj_sha256_" + "a" * 64, object_id_for_sha256("a" * 64))
        self.assertEqual(stable_sha256("中", "A"), stable_sha256("中", "A"))
        with self.assertRaises(ValueError):
            new_public_id("Bad-Prefix")
        with self.assertRaises(ValueError):
            object_id_for_sha256("A" * 64)

    def test_runtime_cannot_overlap_reference(self) -> None:
        settings = Settings(
            project_root=self.project,
            archive_root=self.archive,
            var_root=self.project / "reference" / "runtime",
            database_path=self.project / "reference" / "runtime" / "db" / "platform.sqlite3",
            object_root=self.project / "reference" / "runtime" / "objects",
            migration_root=self.settings.migration_root,
        )
        with self.assertRaises(ConfigurationError):
            settings.validate()

    def test_runtime_cannot_escape_project(self) -> None:
        outside = self.root / "outside"
        settings = Settings(
            project_root=self.project,
            archive_root=self.archive,
            var_root=outside,
            database_path=outside / "db" / "platform.sqlite3",
            object_root=outside / "objects",
            migration_root=self.settings.migration_root,
        )
        with self.assertRaises(ConfigurationError):
            settings.validate()

    def test_business_databases_and_managed_roots_are_isolated(self) -> None:
        settings = self.settings
        databases = {
            settings.database_path,
            settings.archive_database_path,
            settings.research_papers_database_path,
            settings.paper_lab_database_path,
            settings.research_workspace_database_path,
        }
        self.assertEqual(5, len(databases))
        for database in databases:
            self.assertEqual(settings.var_root / "db", database.parent)
        for managed in (
            settings.object_root,
            settings.research_papers_root,
            settings.evidence_replay_root,
            settings.paper_lab_asset_root,
            settings.research_workspace_database_path,
        ):
            self.assertTrue(managed.is_relative_to(settings.var_root))
        self.assertTrue(settings.paper_lab_drop_root.is_relative_to(settings.project_root))
        self.assertFalse(settings.paper_lab_drop_root.is_relative_to(settings.archive_root))
        self.assertTrue(settings.research_workspace_root.is_relative_to(settings.project_root))
        self.assertFalse(settings.research_workspace_root.is_relative_to(settings.archive_root))

    def test_runtime_directory_creation_prepares_evidence_and_paper_lab_roots(self) -> None:
        self.settings.ensure_runtime_directories()
        for directory in (
            self.settings.research_papers_root,
            self.settings.evidence_replay_root,
            self.settings.paper_lab_asset_root,
            self.settings.paper_lab_drop_root,
            self.settings.research_workspace_root,
        ):
            self.assertTrue(directory.is_dir())
        self.assertFalse(self.settings.research_papers_database_path.exists())
        self.assertFalse(self.settings.paper_lab_database_path.exists())

    def test_default_can_bind_an_explicit_frozen_migration_root(self) -> None:
        runtime = self.project / "quant_hub" / "frozen-runtime"
        settings = Settings.default(
            project_root=self.project,
            archive_root=self.archive,
            var_root=runtime,
            migration_root=self.settings.migration_root,
        )
        self.assertEqual(self.settings.migration_root, settings.migration_root)
        self.assertEqual(
            self.settings.migration_root.parent / "research_papers",
            settings.research_papers_migration_root,
        )

    def test_explicit_migration_contract_requires_all_business_domains(self) -> None:
        incomplete_root = self.project / "incomplete-migrations"
        platform_root = incomplete_root / "platform"
        platform_root.mkdir(parents=True)
        with self.assertRaisesRegex(
            ConfigurationError, "archive migration directory is missing"
        ):
            Settings.default(
                project_root=self.project,
                archive_root=self.archive,
                var_root=self.project / "quant_hub" / "isolated-runtime",
                migration_root=platform_root,
            )

    def test_reviewed_runtime_rejects_worktree_migrations(self) -> None:
        with self.assertRaisesRegex(
            ConfigurationError, "must be sealed inside var_root"
        ):
            self.settings.validate_reviewed_runtime()
