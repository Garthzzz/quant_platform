from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import shutil
import tempfile
import unittest
import subprocess
import sys
from unittest.mock import patch

from quant_hub.collaboration.checkpoint import create_sqlite_checkpoint
from quant_hub.ops.recovery_bundle import (
    RecoveryBundleError,
    build_recovery_bundle,
    finalize_recovery_receipt,
    restore_recovery_bundle,
    verify_recovery_bundle,
    _scan_no_secret,
    _scan_regular_payload,
    _scan_sqlite_logical_text,
)
from quant_hub.ops.release_identity import canonical_manifest_bytes, manifest_sha256
from quant_hub.ops.windows_service import quant_hub_package_inventory_sha256


def release_manifest() -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "release-test-v1",
        "built_at": "2026-08-21T06:00:00+08:00",
        "application": {
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": "1" * 64,
            "build_tool_version": "tests/v1",
        },
        "content": {
            "snapshot_id": "snapshot-test-v1",
            "source_inventory_sha256": "2" * 64,
            "ir_sha256": "3" * 64,
            "knowledge_sha256": "4" * 64,
            "search_sha256": "5" * 64,
            "knowledge_enrichment": {"status": "pending"},
        },
        "resources": {"inventory_sha256": "6" * 64},
        "state": {"compatibility": {"comments": {"read": [2], "write": [2]}}},
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
    }


class RecoveryBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release = self.root / "candidate"
        self.release.mkdir()
        self.manifest = release_manifest()
        (self.release / "release_manifest.json").write_bytes(
            canonical_manifest_bytes(self.manifest)
        )
        (self.release / "app").mkdir()
        (self.release / "app" / "server.py").write_text("print('ok')\n", encoding="utf-8")
        (self.release / "resources").mkdir()
        (self.release / "resources" / "paper.bin").write_bytes(b"paper-bytes")

        state = self.root / "state"
        state.mkdir()
        comments = state / "comments.sqlite3"
        connection = sqlite3.connect(comments)
        try:
            connection.executescript("CREATE TABLE comment(id TEXT PRIMARY KEY); INSERT INTO comment VALUES('c1');")
            connection.commit()
        finally:
            connection.close()
        self.checkpoint = create_sqlite_checkpoint(
            sources={"comments": comments},
            checkpoint_root=self.root / "checkpoints",
            checkpoint_id="checkpoint-test-v1",
            state_authority_id="state-test",
            captured_under_release_id="release-test-v1",
            captured_under_manifest_sha256=manifest_sha256(self.manifest),
            captured_at=datetime(2026, 8, 21, 0, tzinfo=UTC),
        )
        self.recovery_root = self.root / "recovery"
        self.recovery_root.mkdir()
        self.restore_tool = self.root / "restore.py"
        self.restore_tool.write_text("# restore entrypoint\n", encoding="utf-8")
        self.runbook = self.root / "RUNBOOK.md"
        self.runbook.write_text("# 恢复\n\n机器验证后执行。\n", encoding="utf-8")
        self.operational = self.root / "operational-source"
        operational_files = {
            "tooling/python/Lib/site-packages/win32/pythonservice.exe": b"python-service",
            "tooling/python/python.exe": b"python-runtime",
            "tooling/python/Lib/site-packages/quant_hub/ops/windows_service.py": b"service-host",
            "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py": b"service-entry",
            "tooling/python/Lib/site-packages/quant_hub/ops/vm_deploy_cli.py": b"deploy-cli",
            "tooling/python/Lib/site-packages/quant_hub/ops/publish_recovery_cli.py": b"recovery-cli",
            "tooling/python/Lib/site-packages/quant_hub/web/access_gate.py": b"access-gate",
            "control/deployment_runtime.json": canonical_manifest_bytes(
                {"schema_version": "qrh-vm-deploy-runtime/v1", "fixture": True}
            ),
        }
        for relative, payload in operational_files.items():
            path = self.operational.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        production = Path(r"D:\quant\quant_platform")
        bindings = {
            "service_executable": "tooling/python/Lib/site-packages/win32/pythonservice.exe",
            "service_python": "tooling/python/python.exe",
            "service_host_module": "tooling/python/Lib/site-packages/quant_hub/ops/windows_service.py",
            "service_entry_module": "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            "deployment_cli_module": "tooling/python/Lib/site-packages/quant_hub/ops/vm_deploy_cli.py",
            "publish_recovery_cli_module": "tooling/python/Lib/site-packages/quant_hub/ops/publish_recovery_cli.py",
            "access_gate_module": "tooling/python/Lib/site-packages/quant_hub/web/access_gate.py",
            "deployment_runtime": "control/deployment_runtime.json",
        }
        candidate = {
            "schema_version": "qrh-windows-service-install-candidate/v1",
            "service_name": "QuantResearchHub",
            "python_class": "quant_hub.ops.windows_service.QuantResearchHubWindowsService",
            "start_type": "automatic",
        }
        for field, relative in bindings.items():
            source = self.operational.joinpath(*relative.split("/"))
            candidate[field] = str(production.joinpath(*relative.split("/")))
            candidate[f"{field}_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        package = self.operational / "tooling/python/Lib/site-packages/quant_hub"
        candidate["quant_hub_package_root"] = str(
            production / "tooling/python/Lib/site-packages/quant_hub"
        )
        candidate["quant_hub_package_inventory_sha256"] = (
            quant_hub_package_inventory_sha256(package)
        )
        candidate_path = self.operational / "control" / "service_install_candidate.json"
        candidate_path.write_bytes(canonical_manifest_bytes(candidate))

    def _build(self):
        return build_recovery_bundle(
            release_root=self.release,
            checkpoint_root=self.checkpoint.root,
            recovery_root=self.recovery_root,
            bundle_id="bundle-test-v1",
            created_at="2026-08-21T08:00:00+08:00",
            restore_tool=self.restore_tool,
            runbook=self.runbook,
            operational_root=self.operational,
            compatibility={"verdict": "compatible", "state_schema": 2},
        )

    def test_bundle_is_complete_verifiable_and_restores_empty_root(self) -> None:
        bundle = self._build()
        report = verify_recovery_bundle(bundle.root)
        self.assertTrue(report.valid, report.errors)
        self.assertEqual("release-test-v1", report.release_id)
        self.assertTrue((bundle.root / "SHA256SUMS").is_file())
        self.assertFalse(any(path.name == "viewer_secret.key" for path in bundle.root.rglob("*")))

        target = self.root / "empty" / "quant_platform"
        target.mkdir(parents=True)
        restored = restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)
        self.assertEqual("release-test-v1", restored.release_id)
        self.assertFalse((target / "audit").exists())
        self.assertTrue((target / "state" / "comments.sqlite3").is_file())
        self.assertTrue((target / "control" / "active_release.json").is_file())
        connection = sqlite3.connect(target / "state" / "comments.sqlite3")
        try:
            self.assertEqual(1, connection.execute("select count(*) from comment").fetchone()[0])
        finally:
            connection.close()
        receipt = finalize_recovery_receipt(
            restored=restored,
            bundle_root=bundle.root,
            recovery_attempt_id="restore-test-v1",
            receipt_id="recovery-test-v1",
            recorded_at="2026-08-21T09:00:00+08:00",
            restore_verification={
                "closure": True,
                "state_restored": True,
                "service_started": True,
                "post_restore": True,
            },
        )
        self.assertTrue(receipt.is_file())

    def test_success_receipt_requires_post_restore_probes(self) -> None:
        bundle = self._build()
        target = self.root / "empty"
        target.mkdir()
        restored = restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)
        with self.assertRaisesRegex(RecoveryBundleError, "all real probes"):
            finalize_recovery_receipt(
                restored=restored,
                bundle_root=bundle.root,
                recovery_attempt_id="restore-test-failed-probe",
                receipt_id="recovery-test-failed-probe",
                recorded_at="2026-08-21T09:00:00+08:00",
                restore_verification={
                    "closure": True,
                    "state_restored": True,
                    "service_started": False,
                    "post_restore": False,
                },
            )
        self.assertFalse((target / "audit").exists())

    def test_shipped_stdlib_tool_restores_without_quant_hub_import(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        restore_tool = project_root / "tools" / "release" / "restore_cold_bundle.py"
        bundle = build_recovery_bundle(
            release_root=self.release,
            checkpoint_root=self.checkpoint.root,
            recovery_root=self.recovery_root,
            bundle_id="bundle-stdlib-v1",
            created_at="2026-08-21T08:00:00+08:00",
            restore_tool=restore_tool,
            runbook=self.runbook,
            operational_root=self.operational,
            compatibility={"verdict": "compatible", "state_schema": 2},
        )
        target = self.root / "stdlib-empty"
        target.mkdir()
        copied_tool = bundle.root / "tools" / "restore" / restore_tool.name
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        loader = (
            "import importlib.util,json,pathlib;"
            f"p=pathlib.Path({str(copied_tool)!r});"
            "s=importlib.util.spec_from_file_location('standalone_restore',p);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            f"print(json.dumps(m.restore(pathlib.Path({str(bundle.root)!r}),pathlib.Path({str(target)!r})),sort_keys=True))"
        )
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                loader,
            ],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("materialized_pending_post_restore_verification", payload["status"])
        self.assertFalse((target / "audit").exists())

    def test_corruption_or_missing_object_fails_closed(self) -> None:
        bundle = self._build()
        (bundle.root / "release" / "resources" / "paper.bin").write_bytes(b"changed")
        self.assertFalse(verify_recovery_bundle(bundle.root).valid)
        target = self.root / "empty"
        target.mkdir()
        with self.assertRaisesRegex(RecoveryBundleError, "not restorable"):
            restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)

    def test_bundle_id_is_immutable(self) -> None:
        first = self._build()
        before = hashlib.sha256((first.root / "recovery_manifest.json").read_bytes()).hexdigest()
        with self.assertRaisesRegex(RecoveryBundleError, "already exists"):
            self._build()
        self.assertEqual(
            before,
            hashlib.sha256((first.root / "recovery_manifest.json").read_bytes()).hexdigest(),
        )

    def test_secret_material_is_rejected_without_echoing_value(self) -> None:
        secret = "sk-" + "x" * 32
        (self.release / "app" / "settings.txt").write_text(
            "provider_key=" + secret + "\n", encoding="utf-8"
        )
        with self.assertRaises(RecoveryBundleError) as context:
            self._build()
        self.assertNotIn(secret, str(context.exception))
        self.assertFalse(any(self.recovery_root.iterdir()))

    def test_reviewed_cookie_source_name_is_scanned_but_state_file_is_blocked(self) -> None:
        source = self.root / "runtime" / "requests" / "cookies.py"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("def cookie_policy():\n    return 'public-code'\n", encoding="utf-8")
        report = _scan_no_secret(self.root, [source])
        self.assertEqual("pass", report["verdict"])
        self.assertEqual("runtime/requests/cookies.py", report["scanned"][0]["path"])

        state = self.root / "runtime" / "browser" / "cookies.json"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(RecoveryBundleError, "forbidden_secret_filename"):
            _scan_no_secret(self.root, [state])

    def test_binary_utf16_and_sqlite_logical_secrets_are_blocked_without_values(self) -> None:
        payloads = {
            "opaque.bin": ("ghp_" + "A" * 32).encode("ascii"),
            "wide.dat": ("sk-proj-" + "B" * 32).encode("utf-16-le"),
        }
        for name, payload in payloads.items():
            with self.subTest(name=name):
                target = self.release / "resources" / name
                target.write_bytes(payload)
                with self.assertRaises(RecoveryBundleError) as caught:
                    self._build()
                self.assertNotIn(payload[:12].decode("ascii", errors="ignore"), str(caught.exception))
                self.assertFalse(any(self.recovery_root.iterdir()))
                target.unlink()

        database = self.root / "state" / "sqlite-secret.sqlite3"
        secret = "Authorization: Bearer " + "C" * 36
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE notes(body TEXT)")
            connection.execute("INSERT INTO notes(body) VALUES (?)", (secret,))
            connection.commit()
        finally:
            connection.close()
        secret_checkpoint = create_sqlite_checkpoint(
            sources={"comments": database},
            checkpoint_root=self.root / "secret-checkpoints",
            checkpoint_id="checkpoint-secret-logical",
            state_authority_id="state-test",
            captured_under_release_id="release-test-v1",
            captured_under_manifest_sha256=manifest_sha256(self.manifest),
            captured_at=datetime(2026, 8, 21, 1, tzinfo=UTC),
        )
        with self.assertRaises(RecoveryBundleError) as caught:
            build_recovery_bundle(
                release_root=self.release,
                checkpoint_root=secret_checkpoint.root,
                recovery_root=self.recovery_root,
                bundle_id="bundle-sqlite-secret",
                created_at="2026-08-21T08:00:00+08:00",
                restore_tool=self.restore_tool,
                runbook=self.runbook,
                operational_root=self.operational,
                compatibility={"verdict": "compatible", "state_schema": 2},
            )
        self.assertNotIn(secret, str(caught.exception))
        self.assertFalse(any(self.recovery_root.iterdir()))

    def test_odd_offset_utf16_secret_crossing_stream_chunk_is_blocked(self) -> None:
        secret = "Authorization: Bearer " + "D" * 40
        # 1 MiB is even; subtracting 31 makes the UTF-16 code-unit alignment
        # odd and places the token across the scanner's block boundary.
        start = 1024 * 1024 - 31
        payload = b"x" * start + secret.encode("utf-16-le") + b"tail"
        target = self.root / "odd-offset-cross-boundary.bin"
        target.write_bytes(payload)
        with self.assertRaises(RecoveryBundleError) as caught:
            _scan_no_secret(self.root, [target])
        self.assertNotIn(secret, str(caught.exception))
        self.assertIn("authorization_bearer", str(caught.exception))

    def test_sqlite_blob_scans_utf8_and_both_utf16_alignments(self) -> None:
        database = self.root / "state" / "blob-encodings.sqlite3"
        github = "ghp_" + "E" * 32
        deepseek = "sk-proj-" + "F" * 32
        bearer = "Authorization: Bearer " + "G" * 40
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE payloads(body BLOB)")
            connection.executemany(
                "INSERT INTO payloads(body) VALUES (?)",
                (
                    (github.encode("utf-8"),),
                    (b"\x00" + deepseek.encode("utf-16-le"),),
                    (b"\x00" + bearer.encode("utf-16-be"),),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        kinds = _scan_sqlite_logical_text(database)
        self.assertTrue(
            {"github_token", "deepseek_openai_key", "authorization_bearer"}
            .issubset(kinds)
        )
        with self.assertRaises(RecoveryBundleError) as caught:
            _scan_no_secret(self.root, [database])
        rendered = str(caught.exception)
        for secret in (github, deepseek, bearer):
            self.assertNotIn(secret, rendered)

    def test_sqlite_fts5_external_content_scans_authority_without_querying_virtual_table(self) -> None:
        database = self.root / "state" / "external-content.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.executescript(
                "CREATE TABLE document_search_projection("
                "rowid INTEGER PRIMARY KEY, body TEXT);"
                "INSERT INTO document_search_projection(body) VALUES ('public research');"
                "CREATE VIRTUAL TABLE document_fts USING fts5("
                "body, content='document_search_projection', content_rowid='rowid');"
                "INSERT INTO document_fts(document_fts) VALUES ('rebuild');"
            )
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(set(), _scan_sqlite_logical_text(database))
        self.assertEqual("pass", _scan_no_secret(self.root, [database])["verdict"])

    def test_sqlite_fts5_external_content_secret_is_blocked_without_leaking_value(self) -> None:
        database = self.root / "state" / "external-content-secret.sqlite3"
        secret = "Authorization: Bearer " + "H" * 40
        connection = sqlite3.connect(database)
        try:
            connection.executescript(
                "CREATE TABLE document_search_projection("
                "rowid INTEGER PRIMARY KEY, body TEXT);"
                "CREATE VIRTUAL TABLE document_fts USING fts5("
                "body, content='document_search_projection', content_rowid='rowid');"
            )
            connection.execute(
                "INSERT INTO document_search_projection(body) VALUES (?)", (secret,)
            )
            connection.execute(
                "INSERT INTO document_fts(document_fts) VALUES ('rebuild')"
            )
            connection.commit()
        finally:
            connection.close()

        self.assertIn(
            "authorization_bearer", _scan_sqlite_logical_text(database)
        )
        with self.assertRaises(RecoveryBundleError) as caught:
            _scan_no_secret(self.root, [database])
        self.assertIn("authorization_bearer", str(caught.exception))
        self.assertNotIn(secret, str(caught.exception))

    def test_sqlite_like_wildcard_cannot_hide_external_content_authority(self) -> None:
        database = self.root / "state" / "literal-sqlite-prefix.sqlite3"
        secret = "Authorization: Bearer " + "Y" * 40
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA page_size=512")
            connection.execute("VACUUM")
            connection.executescript(
                "CREATE TABLE sqliteXprojection("
                "rowid INTEGER PRIMARY KEY, body TEXT);"
                "CREATE VIRTUAL TABLE document_fts USING fts5("
                "body, content='sqliteXprojection', content_rowid='rowid');"
            )
            # SQLite record/overflow pages can physically split this value, so
            # the raw-byte pass alone cannot be treated as a logical row scan.
            connection.execute(
                "INSERT INTO sqliteXprojection(body) VALUES (?)",
                (secret + "B" * 3000,),
            )
            connection.execute(
                "INSERT INTO document_fts(document_fts) VALUES ('rebuild')"
            )
            connection.commit()
        finally:
            connection.close()

        self.assertNotIn(
            "authorization_bearer", _scan_regular_payload(database)[2]
        )
        self.assertIn(
            "authorization_bearer", _scan_sqlite_logical_text(database)
        )
        with self.assertRaises(RecoveryBundleError) as caught:
            _scan_no_secret(self.root, [database])
        self.assertIn("authorization_bearer", str(caught.exception))
        self.assertNotIn(secret, str(caught.exception))

    def test_sqlite_virtual_tables_fail_closed_without_external_fts5_authority(self) -> None:
        fixtures = {
            "contentless": (
                "CREATE VIRTUAL TABLE document_fts USING fts5(body, content='')"
            ),
            "implicit-content": (
                "CREATE VIRTUAL TABLE document_fts USING fts5(body)"
            ),
            "missing-content-table": (
                "CREATE VIRTUAL TABLE document_fts USING fts5("
                "body, content='missing_projection')"
            ),
            "unknown-module": (
                "CREATE VIRTUAL TABLE document_fts USING fts4(body)"
            ),
        }
        for name, statement in fixtures.items():
            with self.subTest(name=name):
                database = self.root / "state" / f"{name}.sqlite3"
                connection = sqlite3.connect(database)
                try:
                    if name == "unknown-module":
                        # Persist an unknown virtual-table declaration without
                        # requiring that unsafe module to be loadable in the
                        # test process.
                        connection.execute("PRAGMA writable_schema=ON")
                        connection.execute(
                            "INSERT INTO sqlite_schema("
                            "type,name,tbl_name,rootpage,sql) VALUES(?,?,?,?,?)",
                            ("table", "document_fts", "document_fts", 0, statement),
                        )
                        connection.execute("PRAGMA writable_schema=OFF")
                    else:
                        connection.execute(statement)
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(RecoveryBundleError):
                    _scan_sqlite_logical_text(database)

        database = self.root / "state" / "virtual-content-authority.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.executescript(
                "CREATE TABLE source_projection(rowid INTEGER PRIMARY KEY, body TEXT);"
                "CREATE VIRTUAL TABLE authority_fts USING fts5("
                "body, content='source_projection', content_rowid='rowid');"
                "CREATE VIRTUAL TABLE document_fts USING fts5("
                "body, content='authority_fts', content_rowid='rowid');"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(RecoveryBundleError, "not an ordinary table"):
            _scan_sqlite_logical_text(database)

    def test_sqlite_internal_table_cannot_be_external_content_authority(self) -> None:
        database = self.root / "state" / "internal-authority.sqlite3"
        secret = "Authorization: Bearer " + "Z" * 40
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA page_size=512")
            connection.execute("VACUUM")
            connection.execute(
                "CREATE TABLE seed(id INTEGER PRIMARY KEY AUTOINCREMENT)"
            )
            connection.execute("INSERT INTO seed DEFAULT VALUES")
            connection.execute(
                "CREATE VIRTUAL TABLE document_fts USING fts5("
                "name, content='sqlite_sequence', content_rowid='rowid')"
            )
            connection.execute(
                "UPDATE sqlite_sequence SET name=? WHERE name='seed'",
                (secret + "B" * 3000,),
            )
            connection.commit()
        finally:
            connection.close()

        self.assertNotIn(
            "authorization_bearer", _scan_regular_payload(database)[2]
        )
        with self.assertRaisesRegex(
            RecoveryBundleError, "authority was not logically scanned"
        ) as caught:
            _scan_sqlite_logical_text(database)
        self.assertNotIn(secret, str(caught.exception))

    def test_sqlite_external_content_index_must_match_scanned_authority(self) -> None:
        database = self.root / "state" / "stale-external-index.sqlite3"
        secret = "Authorization: Bearer " + "W" * 40
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA page_size=512")
            connection.execute("VACUUM")
            connection.executescript(
                "CREATE TABLE projection(rowid INTEGER PRIMARY KEY, body TEXT);"
                "CREATE VIRTUAL TABLE document_fts USING fts5("
                "body, content='projection', content_rowid='rowid');"
            )
            # Deliberately mutate only the FTS index.  The ordinary authority
            # remains empty while the tokenized shadow tables hold the value.
            connection.execute(
                "INSERT INTO document_fts(rowid,body) VALUES (?,?)",
                (1, secret + "B" * 3000),
            )
            connection.commit()
        finally:
            connection.close()

        self.assertNotIn(
            "authorization_bearer", _scan_regular_payload(database)[2]
        )
        with self.assertRaisesRegex(
            RecoveryBundleError, "SQLite logical no-secret scan failed"
        ) as caught:
            _scan_sqlite_logical_text(database)
        self.assertNotIn(secret, str(caught.exception))

    def test_nonempty_restore_target_is_rejected(self) -> None:
        bundle = self._build()
        target = self.root / "not-empty"
        target.mkdir()
        (target / "keep.txt").write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(RecoveryBundleError, "real empty"):
            restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)

    def test_off_host_bundle_restores_only_empty_d_fixture_and_leaves_legacy_c_untouched(self) -> None:
        """Developer recovery storage and the sole .240 target are distinct roles."""

        bundle = self._build()
        bundle_before = {
            path.relative_to(bundle.root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in bundle.root.rglob("*")
            if path.is_file()
        }
        production_vm = self.root / "vm-10.5.1.240"
        target = production_vm / "D" / "quant" / "quant_platform"
        target.mkdir(parents=True)
        legacy_c = production_vm / "C" / "quant_platform"
        legacy_c.mkdir(parents=True)
        legacy_marker = legacy_c / "V39-online.marker"
        legacy_marker.write_bytes(b"legacy-v39-remains-online")
        legacy_before = hashlib.sha256(legacy_marker.read_bytes()).hexdigest()

        restored = restore_recovery_bundle(
            bundle_root=bundle.root,
            empty_target_root=target,
        )

        self.assertEqual("release-test-v1", restored.release_id)
        self.assertEqual(
            legacy_before, hashlib.sha256(legacy_marker.read_bytes()).hexdigest()
        )
        self.assertEqual(
            bundle_before,
            {
                path.relative_to(bundle.root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in bundle.root.rglob("*")
                if path.is_file()
            },
        )
        self.assertEqual(
            {"control", "releases", "state", "tooling", "tools"},
            {path.name for path in target.iterdir()},
        )

    def test_missing_or_tampered_operational_bootstrap_cannot_recover(self) -> None:
        runtime = self.operational / "tooling" / "python" / "python.exe"
        original = runtime.read_bytes()
        runtime.unlink()
        with self.assertRaisesRegex(RecoveryBundleError, "required file"):
            self._build()
        runtime.write_bytes(original)

        bundle = self._build()
        bundled_runtime = (
            bundle.root / "operational" / "tooling" / "python" / "python.exe"
        )
        bundled_runtime.write_bytes(b"tampered-operational-runtime")
        self.assertFalse(verify_recovery_bundle(bundle.root).valid)
        target = self.root / "tampered-empty"
        target.mkdir()
        with self.assertRaisesRegex(RecoveryBundleError, "not restorable"):
            restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)
        self.assertFalse(any(target.iterdir()))

    def test_restore_rejects_reparse_in_target_parent_chain(self) -> None:
        bundle = self._build()
        target = self.root / "vm-10.5.1.240" / "D" / "quant" / "quant_platform"
        target.mkdir(parents=True)
        with patch(
            "quant_hub.ops.recovery_bundle._path_has_reparse",
            return_value=True,
        ):
            with self.assertRaisesRegex(RecoveryBundleError, "real empty"):
                restore_recovery_bundle(
                    bundle_root=bundle.root,
                    empty_target_root=target,
                )
        self.assertFalse(any(target.iterdir()))

    def test_restore_verification_scratch_stays_under_empty_target(self) -> None:
        bundle = self._build()
        target = self.root / "bounded-empty-target"
        target.mkdir()
        original = tempfile.TemporaryDirectory
        observed: list[Path | None] = []

        def tracked(*args, **kwargs):
            raw_dir = kwargs.get("dir")
            # Capture the physical identity while the scratch directory still
            # exists; Windows CI may expose the same parent under 8.3 and long
            # path spellings.
            observed.append(
                Path(raw_dir).resolve(strict=True) if raw_dir is not None else None
            )
            return original(*args, **kwargs)

        with patch(
            "quant_hub.collaboration.checkpoint.tempfile.TemporaryDirectory",
            side_effect=tracked,
        ):
            restore_recovery_bundle(bundle_root=bundle.root, empty_target_root=target)
        self.assertTrue(observed)
        resolved_target = target.resolve(strict=True)
        self.assertTrue(
            all(
                path is not None and path.is_relative_to(resolved_target)
                for path in observed
            )
        )
        self.assertFalse((target / ".recovery-verify-scratch").exists())

    def test_standalone_restore_accepts_only_its_fixed_d_import_staging(self) -> None:
        project_root = Path(__file__).resolve().parents[2]
        restore_tool = project_root / "tools" / "release" / "restore_cold_bundle.py"
        bundle = build_recovery_bundle(
            release_root=self.release,
            checkpoint_root=self.checkpoint.root,
            recovery_root=self.recovery_root,
            bundle_id="bundle-staged-v1",
            created_at="2026-08-21T08:00:00+08:00",
            restore_tool=restore_tool,
            runbook=self.runbook,
            operational_root=self.operational,
            compatibility={"verdict": "compatible", "state_schema": 2},
        )
        target = self.root / "vm-240-staged" / "D" / "quant" / "quant_platform"
        import_parent = target / "tmp" / "recovery-import"
        import_parent.mkdir(parents=True)
        staged = import_parent / bundle.root.name
        shutil.copytree(bundle.root, staged)
        runtime_tmp = target / "tmp" / "recovery-runtime"
        runtime_tmp.mkdir()
        spec = importlib.util.spec_from_file_location(
            "standalone_staged_restore", restore_tool
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.restore(staged, target, staged_under_target=True)
        self.assertTrue(result["empty_root_precondition"])
        self.assertTrue(result["staged_import_pending_cleanup"])
        self.assertTrue((target / "releases" / "release-test-v1").is_dir())
        self.assertTrue((target / "tooling" / "python" / "python.exe").is_file())

        rejected = self.root / "vm-240-rejected" / "D" / "quant" / "quant_platform"
        rejected_import = rejected / "tmp" / "recovery-import"
        rejected_import.mkdir(parents=True)
        rejected_staged = rejected_import / bundle.root.name
        shutil.copytree(bundle.root, rejected_staged)
        (rejected / "unexpected-sibling").mkdir()
        with self.assertRaisesRegex(module.RestoreError, "non-staging"):
            module.restore(rejected_staged, rejected, staged_under_target=True)
        self.assertFalse((rejected / "releases").exists())


if __name__ == "__main__":
    unittest.main()
