from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from quant_hub.ops import revocation_surface as revocation_module
from quant_hub.ops.local_release_identity import canonical_bytes
from quant_hub.ops.local_product_surface import scan_local_product_surface
from quant_hub.ops.revocation_surface import (
    FINDING_CATEGORIES,
    RevocationSurfaceError,
    SURFACE_IDS,
    produce_report_for_test_only,
    validate_report,
    write_report_create_only,
)


FIXED_TIME = datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC)


def _task(
    name: str,
    *,
    execute: str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    arguments: str = r"-File D:\quant\quant_platform\tooling\refresh.ps1",
    interval: str = "",
    kind: str = "MSFT_TaskBootTrigger",
) -> dict[str, object]:
    return {
        "name": name,
        "actions": [
            {
                "kind": "MSFT_TaskExecAction",
                "execute": execute,
                "arguments": arguments,
                "working_directory": r"D:\quant\quant_platform",
                "class_id": "",
                "data": "",
            }
        ],
        "triggers": [
            {
                "kind": kind,
                "repetition_interval": interval,
                "repetition_duration": "",
            }
        ],
    }


class RevocationSurfaceProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        source = self.root / "quant_hub" / "src" / "quant_hub"
        wheel = (
            self.root
            / "tooling"
            / "python"
            / "Lib"
            / "site-packages"
            / "quant_hub"
        )
        source.mkdir(parents=True)
        wheel.mkdir(parents=True)
        (source / "__init__.py").write_text("\n", encoding="utf-8")
        (source / "safe_cli.py").write_text(
            "def main():\n    return 0\n", encoding="utf-8"
        )
        (wheel / "__init__.py").write_text("\n", encoding="utf-8")
        (wheel / "safe_cli.py").write_text(
            "def main():\n    return 0\n", encoding="utf-8"
        )

        (self.root / "quant_hub" / "pyproject.toml").write_text(
            "[project]\nname='quant-research-hub'\nversion='1'\n"
            "[project.scripts]\nqrh-safe='quant_hub.safe_cli:main'\n",
            encoding="utf-8",
        )
        dist = wheel.parent / "quant_research_hub-1.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text(
            "Metadata-Version: 2.4\nName: quant-research-hub\nVersion: 1\n",
            encoding="utf-8",
        )
        (dist / "entry_points.txt").write_text(
            "[console_scripts]\nqrh-safe = quant_hub.safe_cli:main\n",
            encoding="utf-8",
        )

        config = self.root / "config"
        config.mkdir()
        (config / "safe.schema.json").write_text(
            '{"additionalProperties":false,"type":"object"}', encoding="utf-8"
        )
        write_set = {
            "schema_version": "qrh-production-vm-write-set/v1",
            "root": r"D:\quant\quant_platform",
            "areas": [
                "audit",
                "checkout",
                "control",
                "incoming",
                "locks",
                "logs",
                "releases",
                "state",
                "tmp",
                "tooling",
            ],
            "legacy_read_only_sources": [
                r"C:\quant_platform_data\comments.sqlite3",
                r"C:\quant_platform_data\research_workspace.sqlite3",
            ],
            "contract": {
                "root_must_preexist": True,
                "reparse_points_forbidden": True,
                "python_bytecode_disabled": True,
                "temp_and_tmp_inside_root": True,
                "writes_outside_areas_forbidden": True,
                "os_managed_non_file_state": {
                    "type": "windows_scm_service_registration",
                    "service_name": "QuantResearchHub",
                    "image_path": "exact_hash_verified_D_root_candidate_only",
                    "python_class": (
                        "quant_hub.ops.windows_service."
                        "QuantResearchHubWindowsService"
                    ),
                    "project_content_secret_temp_log_cache_on_C_forbidden": True,
                },
            },
        }
        (config / "production_vm_write_set.json").write_text(
            json.dumps(write_set, sort_keys=True), encoding="utf-8"
        )
        runbooks = self.root / "docs" / "runbooks"
        runbooks.mkdir(parents=True)
        (runbooks / "OPERATIONS.md").write_text(
            "# Operations\n\nOnly the exact D active/prior pair is supported.\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _produce(self, tasks: list[dict[str, object]], *, name: str = "report.json"):
        return produce_report_for_test_only(
            self.root,
            windows_tasks=tasks,
            produced_at=FIXED_TIME,
            output_relative_path=f"audit/release-closure/results/stage5/{name}",
        )

    def test_success_is_closed_canonical_create_only_local_evidence(self) -> None:
        path, report = self._produce([_task(r"\QRH\IndexRefresh")])

        self.assertEqual(
            "qrh-stage5-revocation-test-fixture/v1", report["schema_version"]
        )
        self.assertEqual("NON_QUALIFYING_TEST_FIXTURE", report["authority_scope"])
        self.assertEqual(str(self.root), report["exact_project_root"])
        self.assertEqual(list(SURFACE_IDS), [scan["id"] for scan in report["scans"]])
        self.assertEqual(8, report["result"]["surface_checks_passed"])
        self.assertEqual(0, report["result"]["periodic_state_copy_tasks"])
        self.assertEqual(0, report["result"]["outside_d_project_storage"])
        self.assertEqual(0, report["result"]["legacy_protection_exports"])
        self.assertEqual(canonical_bytes(report), path.read_bytes())
        with self.assertRaisesRegex(RevocationSurfaceError, "identity/scope"):
            validate_report(json.loads(path.read_bytes()))

        with self.assertRaisesRegex(RevocationSurfaceError, "identity/scope"):
            write_report_create_only(
                self.root,
                "audit/release-closure/results/stage5/report.json",
                report,
            )

    def test_producer_source_is_inside_its_own_revocation_scan_closure(self) -> None:
        producer = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "quant_hub"
            / "ops"
            / "revocation_surface.py"
        )
        report = scan_local_product_surface(
            root="D:/quant/quant_platform",
            inventory={
                "source_tree": [
                    {
                        "path": "ops/revocation_surface.py",
                        "source": producer.read_text(encoding="utf-8"),
                    }
                ],
                "installed_wheel_entry_names": [],
                "console_entrypoints": [],
                "config_schema_filenames": [],
                "runbook_filenames": [],
                "scheduled_task_names": [],
            },
        )
        self.assertEqual((), report.violations)

    def test_periodic_state_copy_task_fails_closed(self) -> None:
        _, report = self._produce(
            [
                _task(
                    r"\QRH\StateBackup",
                    interval="PT1H",
                    kind="MSFT_TaskTimeTrigger",
                )
            ]
        )

        self.assertLess(report["result"]["surface_checks_passed"], 8)
        self.assertGreater(report["result"]["periodic_state_copy_tasks"], 0)
        categories = {
            finding["category"]
            for scan in report["scans"]
            for finding in scan["findings"]
        }
        self.assertLessEqual(categories, set(FINDING_CATEGORIES))

    def test_outside_d_project_storage_is_mechanically_found(self) -> None:
        _, report = self._produce(
            [
                _task(
                    r"\QRH\ExternalCopy",
                    arguments=(
                        r"-File D:\quant\quant_platform\tooling\copy.ps1 "
                        r"-Target C:\quant_platform_data\comments.sqlite3"
                    ),
                )
            ]
        )

        self.assertEqual(1, report["result"]["outside_d_project_storage"])
        task_scan = next(scan for scan in report["scans"] if scan["id"] == "windows-tasks")
        self.assertEqual("fail", task_scan["outcome"])

    def test_legacy_export_in_source_is_not_trusted_as_absent(self) -> None:
        legacy = self.root / "quant_hub" / "src" / "quant_hub" / "cold_bundle.py"
        legacy.write_text("def publish():\n    return None\n", encoding="utf-8")

        _, report = self._produce([], name="legacy.json")

        self.assertGreater(report["result"]["legacy_protection_exports"], 0)
        source_scan = next(scan for scan in report["scans"] if scan["id"] == "source")
        self.assertEqual("fail", source_scan["outcome"])

    def test_cancelled_public_symbol_and_lazy_export_are_detected(self) -> None:
        source = self.root / "quant_hub" / "src" / "quant_hub" / "safe_cli.py"
        source.write_text(
            "_EXPORTS = ('cold_bundle',)\n"
            "__all__ = [*_EXPORTS, 'cold_' + 'restore', "
            "''.join(('recovery_', 'bundle'))]\n"
            "def cold_bundle():\n    return None\n"
            "def __getattr__(name):\n"
            "    if name in _EXPORTS:\n        return cold_bundle\n"
            "    raise AttributeError(name)\n"
            "globals()['state_' + 'only_backup'] = lambda: None\n",
            encoding="utf-8",
        )

        _, report = self._produce([], name="public-symbol.json")

        self.assertGreater(report["result"]["legacy_protection_exports"], 0)

    def test_source_and_wheel_external_protection_binding_are_detected(self) -> None:
        payload = (
            "from pathlib import Path\n"
            "BACKUP_ROOT = r'E:\\\\vault'\n"
            "def rotate():\n    Path(BACKUP_ROOT).write_text('copy')\n"
        )
        for path in (
            self.root / "quant_hub" / "src" / "quant_hub" / "safe_cli.py",
            self.root
            / "tooling"
            / "python"
            / "Lib"
            / "site-packages"
            / "quant_hub"
            / "safe_cli.py",
        ):
            path.write_text(payload, encoding="utf-8")

        _, report = self._produce([], name="source-storage.json")

        self.assertGreaterEqual(report["result"]["outside_d_project_storage"], 2)

    def test_real_write_sinks_and_local_wrapper_are_detected_but_default_open_is_read(self) -> None:
        payload = (
            "import os\nfrom pathlib import Path\n"
            "ROOT = r'E:\\\\vault'\n"
            "def persist(path, data):\n    Path(path).write_bytes(data)\n"
            "def run():\n"
            "    open(r'C:\\\\legacy\\\\input.json').read()\n"
            "    Path(ROOT).open('w').write('x')\n"
            "    os.replace(r'D:\\\\quant\\\\quant_platform\\\\tmp\\\\x', ROOT)\n"
            "    os.makedirs(ROOT)\n"
            "    persist(ROOT, b'x')\n"
            "    (Path(ROOT) / 'x').write_text('x')\n"
            "    Path(ROOT).joinpath('y').write_text('y')\n"
        )
        for path in (
            self.root / "quant_hub" / "src" / "quant_hub" / "safe_cli.py",
            self.root / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub" / "safe_cli.py",
        ):
            path.write_text(payload, encoding="utf-8")

        _, report = self._produce([], name="write-sinks.json")

        self.assertGreaterEqual(report["result"]["outside_d_project_storage"], 10)
        locations = [
            finding["location"]
            for scan in report["scans"]
            for finding in scan["findings"]
        ]
        self.assertFalse(any("input.json" in location for location in locations))

    def test_control_block_import_is_public_but_comprehension_target_is_not(self) -> None:
        source = self.root / "quant_hub" / "src" / "quant_hub" / "safe_cli.py"
        source.write_text("safe = [0 for cold_bundle in ()]\n", encoding="utf-8")
        _, safe_report = self._produce([], name="safe-comprehension.json")
        self.assertEqual(0, safe_report["result"]["legacy_protection_exports"])

        source.write_text("if True:\n    import os as cold_bundle\n", encoding="utf-8")
        _, unsafe_report = self._produce([], name="control-import.json")
        self.assertGreater(unsafe_report["result"]["legacy_protection_exports"], 0)

    def test_config_and_runbook_external_recovery_roots_are_detected(self) -> None:
        (self.root / "config" / "runtime.json").write_text(
            '{"recovery_root":"E:\\\\vault",'
            '"recoveryRoot":"F:\\\\vault",'
            '"backupDestination":"G:\\\\vault",'
            '"externalStorage":"H:\\\\vault",'
            '"path":"D:\\\\quant\\\\quant_platform evil\\\\state"}',
            encoding="utf-8",
        )
        (self.root / "docs" / "runbooks" / "RECOVERY.md").write_text(
            "Other host recovery root: E:\\vault\n"
            "\u6062\u590d\u6839\u5c5e\u4e8e\u53e6\u4e00\u4e3b\u673a: F:\\safe\n"
            "\u6bcf\u665a\u5c06\u6570\u636e\u5e93\u590d\u5236\u5230 E:\\vault\u3002\n",
            encoding="utf-8",
        )

        _, report = self._produce([], name="external-roots.json")

        self.assertGreaterEqual(report["result"]["outside_d_project_storage"], 8)

    def test_neutral_robocopy_task_and_dot_segment_escape_are_detected(self) -> None:
        tasks = [
            _task(
                r"\Maintenance\Copy",
                execute=r"C:\Windows\System32\robocopy.exe",
                arguments=(
                    r"D:\quant\quant_platform\state E:\vault /MIR"
                ),
                interval="PT1H",
                kind="MSFT_TaskTimeTrigger",
            ),
            _task(
                r"\Maintenance\DotEscape",
                arguments=(
                    r"-Target D:\quant\quant_platform\..\outside\state"
                ),
            ),
            _task(
                r"\Maintenance\UNC",
                execute=r"C:\Windows\System32\robocopy.exe",
                arguments=(
                    r"D:\quant\quant_platform\state \\other-host\share\vault"
                ),
            ),
            _task(
                r"\QRH\BootStateCopy",
                execute=r"C:\Windows\System32\xcopy.exe",
                arguments=(
                    r"D:\quant\quant_platform\state "
                    r"D:\quant\quant_platform\state\shadow"
                ),
                kind="MSFT_TaskBootTrigger",
            ),
        ]

        _, report = self._produce(tasks, name="task-escapes.json")

        self.assertGreater(report["result"]["periodic_state_copy_tasks"], 0)
        self.assertGreaterEqual(report["result"]["outside_d_project_storage"], 3)
        self.assertGreater(report["result"]["legacy_protection_exports"], 0)

    def test_write_set_nested_contract_is_closed(self) -> None:
        path = self.root / "config" / "production_vm_write_set.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["contract"]["recovery_root"] = r"E:\vault"
        path.write_text(json.dumps(value), encoding="utf-8")

        _, report = self._produce([], name="write-set-drift.json")

        self.assertGreater(report["result"]["outside_d_project_storage"], 0)

    def test_write_set_contract_comparison_is_type_exact(self) -> None:
        path = self.root / "config" / "production_vm_write_set.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["contract"]["root_must_preexist"] = 1
        path.write_text(json.dumps(value), encoding="utf-8")

        _, report = self._produce([], name="write-set-type.json")

        self.assertGreater(report["result"]["outside_d_project_storage"], 0)

    def test_schema_relative_regex_is_not_a_path_but_external_drive_pattern_is(self) -> None:
        schema = self.root / "config" / "safe.schema.json"
        schema.write_text(
            json.dumps(
                {
                    "type": "object",
                    "properties": {
                        "relative_path": {
                            "type": "string",
                            "pattern": r"^(?!.*[\\/][^\\]*$).+$",
                        },
                        "path": {"type": "string", "pattern": r"^E:\\vault"},
                    },
                }
            ),
            encoding="utf-8",
        )

        _, report = self._produce([], name="schema-pattern.json")

        schema_scan = next(scan for scan in report["scans"] if scan["id"] == "schema")
        self.assertGreaterEqual(len(schema_scan["findings"]), 1)
        self.assertFalse(
            any("relative_path.pattern" in item["location"] for item in schema_scan["findings"])
        )

    def test_cancelled_bytecode_and_non_exec_project_task_fail_closed(self) -> None:
        cache = self.root / "quant_hub" / "src" / "quant_hub" / "__pycache__"
        cache.mkdir()
        (cache / "cold_bundle.cpython-313.pyc").write_bytes(b"fixture")
        task = _task(r"\QRH\ComHandler")
        task["actions"][0].update(
            {
                "kind": "MSFT_TaskComHandlerAction",
                "execute": "",
                "arguments": "",
                "working_directory": "",
                "class_id": "{00000000-0000-0000-0000-000000000000}",
                "data": "state",
            }
        )

        _, report = self._produce([task], name="bytecode-com-task.json")

        self.assertGreater(report["result"]["legacy_protection_exports"], 0)

    def test_output_rejects_backslash_traversal_and_drive_qualified_component(self) -> None:
        with self.assertRaises(RevocationSurfaceError):
            revocation_module._output_path(
                self.root,
                "audit/release-closure/results/stage5/..\\..\\outside.json",
            )
        with self.assertRaises(RevocationSurfaceError):
            revocation_module._output_path(
                self.root,
                r"audit/release-closure/results/stage5/C:\absolute.json",
            )

    def test_test_only_adapter_rejects_resolved_production_alias(self) -> None:
        alias = self.root / "quant_hub" / ".."
        with mock.patch.object(
            revocation_module, "EXACT_PROJECT_ROOT", str(self.root)
        ), self.assertRaisesRegex(RevocationSurfaceError, "through an alias"):
            revocation_module._inputs_for_test_only(alias, windows_tasks=[])

    def test_report_tamper_and_path_escape_are_rejected(self) -> None:
        _, report = self._produce([], name="base.json")
        tampered = json.loads(canonical_bytes(report))
        tampered["result"]["surface_checks_passed"] = 7
        with self.assertRaises(RevocationSurfaceError):
            revocation_module._validate_test_report(
                tampered, observed_root=str(self.root)
            )
        wrong_type = json.loads(canonical_bytes(report))
        wrong_type["result"]["surface_checks_total"] = 8.0
        with self.assertRaisesRegex(RevocationSurfaceError, "non-negative integers"):
            revocation_module._validate_test_report(
                wrong_type, observed_root=str(self.root)
            )
        noncanonical_time = json.loads(canonical_bytes(report))
        noncanonical_time["produced_at"] = "2026-08-31T20:00:00+08:00"
        noncanonical_time["report_id"] = "arbitrary-valid-id"
        noncanonical_time.pop("report_sha256")
        noncanonical_time["report_sha256"] = hashlib.sha256(
            canonical_bytes(noncanonical_time)
        ).hexdigest()
        with self.assertRaisesRegex(RevocationSurfaceError, "not canonical"):
            revocation_module._validate_test_report(
                noncanonical_time, observed_root=str(self.root)
            )
        material = dict(report)
        claimed = material.pop("report_sha256")
        self.assertEqual(hashlib.sha256(canonical_bytes(material)).hexdigest(), claimed)
        with self.assertRaisesRegex(RevocationSurfaceError, "Stage 5 audit"):
            revocation_module._write_test_report_create_only(
                self.root, "../escape.json", report
            )


if __name__ == "__main__":
    unittest.main()
