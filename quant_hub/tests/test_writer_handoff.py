from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from quant_hub.collaboration.checkpoint import (
    CheckpointError,
    create_sqlite_checkpoint,
)
from quant_hub.ops.local_release_identity import identity_sha256
from quant_hub.ops.release_identity import canonical_manifest_bytes, manifest_sha256
from quant_hub.ops.vm_service_cli import production_runtime_document
from quant_hub.ops.windows_service import (
    WindowsServiceError,
    authorize_writer_handoff_service_start,
)
from quant_hub.ops.writer_handoff import (
    FAILURE_SCHEMA,
    ExactSuccessor,
    LEGACY_SERVER,
    PORT,
    SUCCESS_SCHEMA,
    LegacyProcess,
    RuntimeObservation,
    V39Baseline,
    WriterHandoffError,
    apply_writer_handoff,
    finalize_writer_handoff,
    inspect_d_closure,
    inspect_writer_handoff,
    persist_writer_handoff_inspection,
    seed_v39_access_identity,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 21, 4, 0, tzinfo=UTC)
NONCE = "12" * 24
H = {str(index): str(index) * 64 for index in range(1, 10)}


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_manifest_bytes(value))


def _database(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE marker(value TEXT NOT NULL)")
        connection.execute("INSERT INTO marker(value) VALUES (?)", (value,))
        connection.commit()
    finally:
        connection.close()


def _value(path: Path) -> str:
    connection = sqlite3.connect(path)
    try:
        return str(connection.execute("SELECT value FROM marker").fetchone()[0])
    finally:
        connection.close()


def _release(baseline: V39Baseline | None = None) -> dict[str, object]:
    inventory = {"schema_version": "qrh-release-file-inventory/v1", "files": []}
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "v39-baseline-20260731-hotfix1",
        "built_at": "2026-07-31T10:04:18Z",
        "application": {
            "commit_sha": "0" * 40,
            "tracked_tree_sha256": H["1"],
            "build_tool_version": "writer-handoff-tests/v1",
            "source_kind": "legacy_broadcast",
            "legacy_deployment_id": "quant-hub-v39-company-broadcast-20260731-hotfix1",
            "source_archive_sha256": H["8"],
            "source_package_manifest_sha256": H["9"],
        },
        "content": {
            "snapshot_id": "v39-content-20260731-hotfix1",
            "source_inventory_sha256": H["2"],
            "ir_sha256": H["3"],
            "knowledge_sha256": H["4"],
            "search_sha256": H["5"],
            "knowledge_enrichment": {
                "status": "not_applicable",
                "reason": "legacy_v39_baseline",
            },
        },
        "resources": {"inventory_sha256": manifest_sha256(inventory)},
        "state": {
            "compatibility": {
                "comments": {"read": [1, 2], "write": [1, 2]},
                "research_workspace": {"read": [1, 2, 3], "write": [1, 2, 3]},
                "rollback_policy": "expand_only_no_down_migration",
            }
        },
        "inventory": inventory,
    }


def _pending_access_seed(root: Path) -> tuple[V39Baseline, bytes]:
    default_digest = bytes.fromhex("ab" * 32)
    source = (
        "import hashlib\n"
        "import os\n"
        "ACCESS_PASSWORD_SALT = bytes.fromhex(\"ae829f253a022e21e2b53ddd97c712b8\")\n"
        "ACCESS_PASSWORD_ITERATIONS = 600_000\n"
        f"DEFAULT_ACCESS_PASSWORD_DIGEST = bytes.fromhex(\"{default_digest.hex()}\")\n"
        "def _access_password_digest() -> bytes:\n"
        "    configured = os.environ.get(\"VIEWER_ACCESS_PASSWORD\")\n"
        "    if configured is None:\n"
        "        return DEFAULT_ACCESS_PASSWORD_DIGEST\n"
        "    if not configured:\n"
        "        raise RuntimeError(\"override must not be empty\")\n"
        "    return hashlib.pbkdf2_hmac(\n"
        "        \"sha256\",\n"
        "        configured.encode(\"utf-8\"),\n"
        "        ACCESS_PASSWORD_SALT,\n"
        "        ACCESS_PASSWORD_ITERATIONS,\n"
        "    )\n"
    ).encode("utf-8")
    inventory = {
        "schema_version": "qrh-release-file-inventory/v2",
        "files": [
            {
                "path": "tools/viewer/server.py",
                "bytes": len(source),
                "sha256": hashlib.sha256(source).hexdigest(),
            }
        ],
    }
    release = {
        "schema_version": "qrh-release-manifest/v2",
        "release_id": "v39-baseline-20260731-hotfix1",
        "built_at": "2026-07-31T10:04:18Z",
        "application": {
            "source_kind": "legacy_broadcast",
            "source_archive_sha256": H["8"],
            "legacy_deployment_id": "quant-hub-v39-company-broadcast-20260731-hotfix1",
            "build_tool_version": "writer-handoff-tests/v2",
            "provenance": {
                "builder": "writer-handoff-tests",
                "labels": ["exact-local-active-prior", "legacy-v39-baseline"],
            },
        },
        "content": {
            "snapshot_id": "v39-content-20260731-hotfix1",
            "source_inventory_sha256": H["2"],
            "ir_sha256": H["3"],
            "knowledge_sha256": H["4"],
            "search_sha256": H["5"],
            "page_projection_sha256": H["6"],
            "mcp_sha256": H["7"],
            "active_membership_sha256": H["8"],
            "knowledge_enrichment": {"status": "not_applicable"},
            "presentation": {"language": "zh-CN"},
        },
        "resources": {"inventory_sha256": identity_sha256(inventory)},
        "state": {
            "compatibility": {
                "comments": {"read": [1, 2], "write": [1, 2]},
                "research_workspace": {"read": [1, 2, 3], "write": [1, 2, 3]},
                "rollback_policy": "expand_only_no_down_migration",
            }
        },
        "inventory": inventory,
    }
    baseline = V39Baseline(identity_sha256(release))
    candidate = root / "incoming" / f"{baseline.release_id}.partial"
    server = candidate / "tools" / "viewer" / "server.py"
    server.parent.mkdir(parents=True)
    server.write_bytes(source)
    _write_json(candidate / "release_manifest.json", release)
    (root / "state").mkdir()
    return baseline, default_digest


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        temporary_root = Path(self.temporary.name).resolve(strict=True)
        self.root = temporary_root / "D-root"
        self.root.mkdir()
        release = _release()
        self.baseline = V39Baseline(manifest_sha256(release))
        release_root = self.root / "releases" / self.baseline.release_id
        release_root.mkdir(parents=True)
        _write_json(release_root / "release_manifest.json", release)
        _write_json(
            self.root / "control" / "active_release.json",
            {
                "schema_version": "qrh-active-release/v1",
                "release_id": self.baseline.release_id,
                "release_path": str(release_root.resolve()),
                "manifest_sha256": self.baseline.manifest_sha256,
            },
        )
        _write_json(
            self.root / "control" / "deployment_runtime.json",
            production_runtime_document(),
        )
        _write_json(
            self.root / "control" / "service_install_candidate.json",
            {"schema_version": "test-service-binding/v1", "closed": True},
        )
        state = self.root / "state"
        state.mkdir()
        (state / "viewer_access_password.digest").write_text("a" * 64 + "\n", encoding="ascii")
        _database(state / "comments.sqlite3", "d-comments-old")
        _database(state / "research_workspace.sqlite3", "d-workspace-old")
        self.legacy = temporary_root / "C-state"
        _database(self.legacy / "comments.sqlite3", "c-comments-final")
        _database(self.legacy / "research_workspace.sqlite3", "c-workspace-final")

    @property
    def legacy_sources(self) -> dict[str, Path]:
        return {
            "comments": self.legacy / "comments.sqlite3",
            "research_workspace": self.legacy / "research_workspace.sqlite3",
        }

    def closure(self, root: Path, baseline: V39Baseline) -> dict[str, object]:
        with mock.patch(
            "quant_hub.ops.writer_handoff.verify_installed_operational_bindings",
            return_value={"service_python": root / "tooling" / "python.exe"},
        ):
            return dict(inspect_d_closure(root, baseline))

    def close(self) -> None:
        self.temporary.cleanup()


class FakeRuntime:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.process = LegacyProcess(
            3901,
            r"C:\Miniconda3\envs\quant_hub\python.exe",
            (
                r"C:\Miniconda3\envs\quant_hub\python.exe",
                "-I",
                str(LEGACY_SERVER),
            ),
            "c" * 64,
            "d" * 64,
        )
        self.legacy_running = True
        self.d_status = "stopped"
        self.open = False
        self.toctou = False
        self.observe_calls = 0
        self.d_external_open_calls = 0
        self.start_failure = ""
        self.probe_ok = True
        self.generate_session_key = True
        self.events: list[str] = []
        self.start_legacy_count = 0
        self.bridge_attempts: tuple[str, str] | None = None
        self.bridge_failure = False
        self.pair_control_ok = True
        self.pair_control_checks = 0

    def observe(self, port: int) -> RuntimeObservation:
        self.observe_calls += 1
        process = self.process
        if self.toctou and self.observe_calls >= 2 and self.legacy_running:
            process = LegacyProcess(
                3902,
                process.executable,
                process.argv,
                process.executable_sha256,
                process.server_sha256,
            )
        if self.legacy_running:
            deployment = {
                "schema_version": "qrh-company-broadcast-health/v1",
                "status": "ok",
                "deployment_id": "quant-hub-v39-company-broadcast-20260731-hotfix1",
                "pid": process.pid,
                "port": port,
            }
            listeners = (process.pid,)
            legacy_process = process
        else:
            deployment = None
            legacy_process = None
            listeners = (8801,) if self.open else ()
        return RuntimeObservation(
            ("10.5.1.240",),
            listeners,
            deployment,
            legacy_process,
            {
                "service_name": "QuantResearchHub",
                "installed": True,
                "status": self.d_status,
                "binding_verified": True,
            },
        )

    def stop_legacy(self, expected: LegacyProcess) -> None:
        if expected != self.process or not self.legacy_running:
            raise RuntimeError("wrong legacy PID")
        self.events.append("stop-c")
        self.legacy_running = False

    def wait_port_free(self, port: int) -> bool:
        self.events.append("port-free")
        return not self.legacy_running and not self.open

    def start_d_service(self, service_name: str) -> None:
        self.events.append("start-d")
        if self.start_failure == "before_open":
            raise RuntimeError("D start failed")
        self.d_status = "running"
        if self.generate_session_key:
            (self.root / "state" / "viewer_secret.key").write_text(
                "b" * 64 + "\n", encoding="ascii"
            )
        self.open = True
        if self.start_failure == "after_open":
            raise RuntimeError("D opened then failed")

    def activate_exact_pair(
        self,
        baseline: V39Baseline,
        successor: ExactSuccessor,
        bootstrap_attempt_id: str,
        activation_attempt_id: str,
    ) -> dict[str, object]:
        self.events.append("bridge-r0-r1")
        self.bridge_attempts = (bootstrap_attempt_id, activation_attempt_id)
        if self.bridge_failure:
            raise RuntimeError("exact bridge failed before ingress")
        self.d_status = "running"
        (self.root / "state" / "viewer_secret.key").write_text(
            "b" * 64 + "\n", encoding="ascii"
        )
        self.open = True
        return {
            "schema_version": "qrh-v39-exact-pair-bridge-result/v1",
            "status": "activated_pair",
            "pair": {
                "active": {
                    "release_id": successor.release_id,
                    "manifest_sha256": successor.manifest_sha256,
                },
                "prior": {
                    "release_id": baseline.release_id,
                    "manifest_sha256": baseline.manifest_sha256,
                },
            },
        }

    def stop_d_service(self, service_name: str) -> None:
        self.events.append("stop-d")
        self.d_status = "stopped"
        self.open = False

    def d_external_open(self, port: int) -> bool:
        self.d_external_open_calls += 1
        return self.open

    def probe_d(self, baseline: V39Baseline) -> dict[str, object]:
        self.events.append("probe-d")
        value = {
            "release_id": baseline.release_id,
            "manifest_sha256": baseline.manifest_sha256,
            "snapshot_id": baseline.snapshot_id,
            "writer_authority": "D-active",
            "unique_d_listener": True,
            "legacy_pid_stopped": not self.legacy_running,
            "browser": True,
            "api": True,
            "resource": True,
            "legacy_restart_fenced": True,
        }
        if not self.probe_ok:
            value["api"] = False
        return value

    def verify_exact_pair_control(
        self, baseline: V39Baseline, successor: ExactSuccessor
    ) -> dict[str, object]:
        self.pair_control_checks += 1
        if not self.pair_control_ok:
            raise WriterHandoffError("fixture prior binding missing")
        return {
            "schema_version": "qrh-writer-handoff-exact-pair-proof/v1",
            "pair": {
                "active": {
                    "release_id": successor.release_id,
                    "manifest_sha256": successor.manifest_sha256,
                },
                "prior": {
                    "release_id": baseline.release_id,
                    "manifest_sha256": baseline.manifest_sha256,
                },
            },
            "state_identity_sha256": "7" * 64,
            "retention_aggregate_sha256": "8" * 64,
        }

    def start_legacy(self, expected: LegacyProcess) -> None:
        self.events.append("start-c-exact-argv")
        self.start_legacy_count += 1
        self.legacy_running = True

    def verify_legacy_restored(
        self, expected: LegacyProcess, deployment_id: str, port: int
    ) -> bool:
        self.events.append("verify-c")
        return self.legacy_running and not self.open


class V39AccessIdentitySeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve(strict=True) / "D-root"
        self.root.mkdir()
        self.baseline, self.default_digest = _pending_access_seed(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_pending_r0_seeds_identity_before_first_pair_exists(self) -> None:
        result = seed_v39_access_identity(
            vm_root=self.root,
            baseline=self.baseline,
            allow_test_root=True,
            override_detector=lambda: False,
        )

        self.assertEqual("seeded", result["status"])
        self.assertTrue(result["protected_access_identity_present"])
        self.assertEqual(
            self.default_digest.hex() + "\n",
            (self.root / "state" / "viewer_access_password.digest").read_text(
                encoding="ascii"
            ),
        )

    def test_pending_r0_rejects_an_existing_release_pair(self) -> None:
        _write_json(
            self.root / "control" / "active_release.json",
            {
                "schema_version": "qrh-active-release/v1",
                "release_id": self.baseline.release_id,
                "release_path": str(
                    self.root / "releases" / self.baseline.release_id
                ),
                "manifest_sha256": self.baseline.manifest_sha256,
            },
        )

        with self.assertRaisesRegex(WriterHandoffError, "absent D release pair"):
            seed_v39_access_identity(
                vm_root=self.root,
                baseline=self.baseline,
                allow_test_root=True,
                override_detector=lambda: False,
            )
        self.assertFalse(
            (self.root / "state" / "viewer_access_password.digest").exists()
        )

    def test_pending_r0_rejects_server_bytes_outside_manifest(self) -> None:
        server = (
            self.root
            / "incoming"
            / f"{self.baseline.release_id}.partial"
            / "tools"
            / "viewer"
            / "server.py"
        )
        server.write_bytes(server.read_bytes() + b"\n# changed\n")

        with self.assertRaisesRegex(WriterHandoffError, "bytes differ"):
            seed_v39_access_identity(
                vm_root=self.root,
                baseline=self.baseline,
                allow_test_root=True,
                override_detector=lambda: False,
            )
        self.assertFalse(
            (self.root / "state" / "viewer_access_password.digest").exists()
        )

    def test_pending_r0_rejects_access_override_without_reading_it(self) -> None:
        with self.assertRaisesRegex(WriterHandoffError, "override evidence exists"):
            seed_v39_access_identity(
                vm_root=self.root,
                baseline=self.baseline,
                allow_test_root=True,
                override_detector=lambda: True,
            )
        self.assertFalse(
            (self.root / "state" / "viewer_access_password.digest").exists()
        )


class WriterHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()
        self.runtime = FakeRuntime(self.fixture.root)

    def tearDown(self) -> None:
        self.fixture.close()

    def test_production_state_replace_keeps_fresh_files_pinned_through_move(self) -> None:
        from quant_hub.ops import writer_handoff as module

        checkpoint_root = (
            self.fixture.root
            / "tmp"
            / "writer-handoff"
            / "attempt-pin"
            / "checkpoints"
            / "checkpoint-pin"
        )
        checkpoint_root.mkdir(parents=True)
        sources = {
            "comments": self.fixture.legacy / "comments.sqlite3",
            "research_workspace": self.fixture.legacy
            / "research_workspace.sqlite3",
        }
        payloads = {name: path.read_bytes() for name, path in sources.items()}
        with mock.patch.object(
            module,
            "PRODUCTION_VM_ROOT",
            self.fixture.root,
        ), mock.patch.object(
            module,
            "_read_production_sqlite_checkpoint_bytes",
            return_value=payloads,
        ) as read_checkpoint:
            module._replace_d_state(
                root=self.fixture.root,
                checkpoint_root=checkpoint_root,
                attempt_id="attempt-pin",
                expected_manifest_sha256="a" * 64,
                allow_test_root=False,
            )
        read_checkpoint.assert_called_once_with(
            checkpoint_root,
            attempt_id="attempt-pin",
            expected_manifest_sha256="a" * 64,
        )
        self.assertEqual(
            "c-comments-final",
            _value(self.fixture.root / "state" / "comments.sqlite3"),
        )
        self.assertEqual(
            "c-workspace-final",
            _value(self.fixture.root / "state" / "research_workspace.sqlite3"),
        )
        self.assertFalse(
            (
                self.fixture.root
                / "tmp"
                / "writer-handoff"
                / "attempt-pin"
                / "state"
            ).exists()
        )

    def inspect(self) -> dict[str, object]:
        return dict(
            inspect_writer_handoff(
                vm_root=self.fixture.root,
                baseline=self.fixture.baseline,
                runtime=self.runtime,
                nonce=NONCE,
                inspected_at=NOW,
                allow_test_root=True,
                closure_verifier=self.fixture.closure,
            )
        )

    def apply(self, receipt: dict[str, object], **changes):
        arguments = {
            "vm_root": self.fixture.root,
            "baseline": self.fixture.baseline,
            "runtime": self.runtime,
            "inspection_receipt": receipt,
            "expected_inspection_sha256": manifest_sha256(receipt),
            "nonce": NONCE,
            "now": lambda: NOW + timedelta(minutes=1),
            "id_factory": lambda: "a" * 32,
            "allow_test_root": True,
            "closure_verifier": self.fixture.closure,
            "legacy_sources": self.fixture.legacy_sources,
        }
        arguments.update(changes)
        return apply_writer_handoff(**arguments)

    @staticmethod
    def production_runtime_shell():
        from quant_hub.ops.writer_handoff import WindowsHandoffRuntime

        runtime = object.__new__(WindowsHandoffRuntime)
        runtime.root = Path(r"D:\quant\quant_platform")
        return runtime

    def test_production_inspect_rejects_fake_runtime_before_root_or_observe(self) -> None:
        successor = ExactSuccessor("release-r1", "e" * 64, "snapshot-r1")
        with mock.patch(
            "quant_hub.ops.writer_handoff._root",
            side_effect=AssertionError("production root must remain untouched"),
        ):
            with self.assertRaisesRegex(
                WriterHandoffError, "internally constructed"
            ):
                inspect_writer_handoff(
                    vm_root=Path(r"D:\quant\quant_platform"),
                    baseline=self.fixture.baseline,
                    successor=successor,
                    runtime=self.runtime,
                    nonce=NONCE,
                )
        self.assertEqual(0, self.runtime.observe_calls)

    def test_production_inspect_rejects_helper_shadowed_exact_runtime_before_root(self) -> None:
        successor = ExactSuccessor("release-r1", "e" * 64, "snapshot-r1")
        runtime = self.production_runtime_shell()
        runtime._powershell = lambda _script: "{}"
        runtime._listener_pids = lambda _port: ()
        with mock.patch(
            "quant_hub.ops.writer_handoff._root",
            side_effect=AssertionError("production root must remain untouched"),
        ):
            with self.assertRaisesRegex(
                WriterHandoffError, "internally constructed"
            ):
                inspect_writer_handoff(
                    vm_root=Path(r"D:\quant\quant_platform"),
                    baseline=self.fixture.baseline,
                    successor=successor,
                    runtime=runtime,
                    nonce=NONCE,
                )

    def test_production_inspect_rejects_injected_proofs_before_root(self) -> None:
        successor = ExactSuccessor("release-r1", "e" * 64, "snapshot-r1")
        calls: list[str] = []

        def fabricated_closure(_root: Path, _baseline: V39Baseline):
            calls.append("closure")
            return {}

        with mock.patch(
            "quant_hub.ops.writer_handoff._root",
            side_effect=AssertionError("production root must remain untouched"),
        ):
            with self.assertRaisesRegex(
                WriterHandoffError, "closure verifier is not injectable"
            ):
                inspect_writer_handoff(
                    vm_root=Path(r"D:\quant\quant_platform"),
                    baseline=self.fixture.baseline,
                    successor=successor,
                    nonce=NONCE,
                    closure_verifier=fabricated_closure,
                )
        self.assertEqual([], calls)

    def test_production_apply_and_finalize_reject_all_injected_seams_before_root(self) -> None:
        from quant_hub.ops import writer_handoff as module

        successor = ExactSuccessor("release-r1", "e" * 64, "snapshot-r1")
        base = {
            "vm_root": Path(r"D:\quant\quant_platform"),
            "baseline": self.fixture.baseline,
            "successor": successor,
            "inspection_receipt": {},
            "expected_inspection_sha256": "f" * 64,
            "nonce": NONCE,
        }
        injected = (
            {"runtime": self.runtime},
            {"now": lambda: NOW},
            {"id_factory": lambda: "a" * 32},
            {"closure_verifier": lambda _root, _baseline: {}},
            {"successor_verifier": lambda _root, _successor: {}},
            {"checkpoint_builder": lambda **_arguments: None},
            {"legacy_sources": {}},
        )
        with mock.patch.object(
            module,
            "_root",
            side_effect=AssertionError("production root must remain untouched"),
        ):
            for change in injected:
                with self.subTest(change=tuple(change)):
                    with self.assertRaises(WriterHandoffError):
                        apply_writer_handoff(**base, **change)
            with self.assertRaisesRegex(
                WriterHandoffError, "finalize clock is not injectable"
            ):
                finalize_writer_handoff(
                    vm_root=base["vm_root"],
                    baseline=self.fixture.baseline,
                    successor=successor,
                    attempt_id="handoff-production-seam-test",
                    nonce=NONCE,
                    now=lambda: NOW,
                )
            with self.assertRaisesRegex(
                WriterHandoffError, "internally constructed"
            ):
                finalize_writer_handoff(
                    vm_root=base["vm_root"],
                    baseline=self.fixture.baseline,
                    successor=successor,
                    runtime=self.runtime,
                    attempt_id="handoff-production-seam-test",
                    nonce=NONCE,
                )
        self.assertEqual(0, self.runtime.observe_calls)

    def test_inspect_closes_v39_state_control_and_service(self) -> None:
        receipt = self.inspect()
        observation = receipt["observation"]
        self.assertEqual("evidence_only", receipt["authority"])
        self.assertFalse(receipt["mutation_performed"])
        self.assertEqual(3901, observation["legacy_process"]["pid"])
        self.assertEqual(self.fixture.baseline.manifest_sha256, observation["v39"]["manifest_sha256"])
        self.assertNotIn("recovery", observation["d"])
        self.assertEqual(
            "pending_first_production_start",
            observation["d"]["protected_session_key_status"],
        )
        rendered = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("a" * 64, rendered)  # protected access digest is not recorded
        self.assertFalse((self.fixture.root / "audit" / "writer-handoff").exists())

    def test_prepare_intent_persists_exact_canonical_receipt_only(self) -> None:
        result = persist_writer_handoff_inspection(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            nonce=NONCE,
            inspected_at=NOW,
            allow_test_root=True,
            closure_verifier=self.fixture.closure,
        )
        path = Path(str(result["inspection_receipt"]))
        self.assertEqual(
            self.fixture.root
            / "control"
            / "writer-handoff-intents"
            / f"writer-handoff-inspection-{NONCE}.json",
            path,
        )
        raw = path.read_bytes()
        receipt = json.loads(raw.decode("utf-8"))
        self.assertEqual(canonical_manifest_bytes(receipt), raw)
        self.assertEqual(
            manifest_sha256(receipt), result["inspection_sha256"]
        )
        self.assertEqual("evidence_only", receipt["authority"])
        self.assertFalse(receipt["mutation_performed"])
        self.assertTrue(self.runtime.legacy_running)
        self.assertEqual([], self.runtime.events)
        with self.assertRaisesRegex(
            WriterHandoffError, "immutable handoff receipt ID already exists"
        ):
            persist_writer_handoff_inspection(
                vm_root=self.fixture.root,
                baseline=self.fixture.baseline,
                runtime=self.runtime,
                nonce=NONCE,
                inspected_at=NOW,
                allow_test_root=True,
                closure_verifier=self.fixture.closure,
            )

    def test_wrong_pid_or_server_path_is_rejected_read_only(self) -> None:
        process = self.runtime.process
        self.runtime.process = LegacyProcess(
            process.pid,
            process.executable,
            (process.executable, "-I", r"C:\tmp\server.py"),
            process.executable_sha256,
            process.server_sha256,
        )
        with self.assertRaises(WriterHandoffError):
            self.inspect()
        self.assertTrue(self.runtime.legacy_running)
        self.assertEqual([], self.runtime.events)

    def test_invalid_existing_session_key_is_rejected_before_handoff(self) -> None:
        (self.fixture.root / "state" / "viewer_secret.key").write_text(
            "not-a-valid-runtime-key\n", encoding="ascii"
        )
        with self.assertRaises(WriterHandoffError):
            self.inspect()
        self.assertTrue(self.runtime.legacy_running)
        self.assertEqual([], self.runtime.events)

    def test_hash_nonce_and_toctou_are_fail_closed_before_pid_stop(self) -> None:
        receipt = self.inspect()
        with self.assertRaises(WriterHandoffError):
            self.apply(receipt, expected_inspection_sha256="f" * 64)
        self.assertTrue(self.runtime.legacy_running)
        self.runtime.toctou = True
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertFalse(result.legacy_rollback_attempted)
        self.assertTrue(self.runtime.legacy_running)
        self.assertNotIn("stop-c", self.runtime.events)
        failure = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(FAILURE_SCHEMA, failure["schema_version"])
        self.assertFalse(failure["success_activation_recorded"])

    def test_final_checkpoint_failure_restores_exact_legacy_without_restart_script(self) -> None:
        receipt = self.inspect()

        def fail_legacy(**arguments):
            if arguments["state_authority_id"] == "legacy-c-final":
                raise CheckpointError("fixture final checkpoint failure")
            return create_sqlite_checkpoint(**arguments)

        result = self.apply(receipt, checkpoint_builder=fail_legacy)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.legacy_rollback_attempted)
        self.assertTrue(result.legacy_rollback_succeeded)
        self.assertEqual(1, self.runtime.start_legacy_count)
        self.assertIn("start-c-exact-argv", self.runtime.events)
        self.assertNotIn("restart.py", " ".join(self.runtime.events))

    def test_d_start_failure_before_listener_restores_c_and_original_d_state(self) -> None:
        receipt = self.inspect()
        self.runtime.start_failure = "before_open"
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.legacy_rollback_succeeded)
        self.assertFalse(result.rollback_blocked)
        self.assertEqual("d-comments-old", _value(self.fixture.root / "state" / "comments.sqlite3"))
        self.assertEqual("d-workspace-old", _value(self.fixture.root / "state" / "research_workspace.sqlite3"))
        self.assertLess(self.runtime.events.index("stop-c"), self.runtime.events.index("start-c-exact-argv"))
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("legacy_restored_fenced", journal["phase"])
        with self.assertRaises(WindowsServiceError):
            authorize_writer_handoff_service_start(
                self.fixture.root,
                {
                    "release_id": self.fixture.baseline.release_id,
                    "manifest_sha256": self.fixture.baseline.manifest_sha256,
                },
            )

    def test_failed_terminal_cleanup_can_be_retried_and_resolved(self) -> None:
        receipt = self.inspect()
        self.runtime.start_failure = "before_open"
        with mock.patch(
            "quant_hub.ops.writer_handoff._cleanup_handoff_transients",
            return_value=False,
        ):
            failed = self.apply(receipt)
        self.assertEqual("handoff_transient_cleanup_failed", failed.error_code)
        journal_path = self.fixture.root / "control" / "writer_handoff_pending.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        attempt_id = str(journal["attempt_id"])
        self.assertTrue(
            (self.fixture.root / "tmp" / "writer-handoff" / attempt_id).is_dir()
        )

        resolved = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=attempt_id,
            nonce=NONCE,
            allow_test_root=True,
        )
        self.assertFalse(resolved.succeeded)
        self.assertFalse(journal_path.exists())
        self.assertFalse(
            (self.fixture.root / "tmp" / "writer-handoff" / attempt_id).exists()
        )

    def test_failure_terminal_is_durable_before_cleanup_crash(self) -> None:
        from quant_hub.ops import writer_handoff as module

        receipt = self.inspect()
        self.runtime.start_failure = "before_open"
        original_cleanup = module._cleanup_handoff_transients

        def cleanup_then_crash(**kwargs):
            self.assertTrue(original_cleanup(**kwargs))
            raise SystemExit("crash after failure cleanup returned")

        with mock.patch.object(
            module,
            "_cleanup_handoff_transients",
            side_effect=cleanup_then_crash,
        ), self.assertRaises(SystemExit):
            self.apply(receipt)

        journal_path = self.fixture.root / "control" / "writer_handoff_pending.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertEqual("legacy_restored_fenced", journal["phase"])
        self.assertIsInstance(journal["commit_evidence"], dict)
        attempt_id = str(journal["attempt_id"])
        self.assertFalse(
            (self.fixture.root / "tmp" / "writer-handoff" / attempt_id).exists()
        )
        resolved = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=attempt_id,
            nonce=NONCE,
            allow_test_root=True,
        )
        self.assertFalse(resolved.succeeded)
        self.assertTrue(resolved.legacy_rollback_succeeded)
        self.assertFalse(journal_path.exists())
        self.assertEqual(
            "d-comments-old",
            _value(self.fixture.root / "state" / "comments.sqlite3"),
        )

    def test_fresh_finalize_reobserves_resigned_failure_before_clearing_fence(
        self,
    ) -> None:
        from quant_hub.ops import writer_handoff as module

        receipt = self.inspect()
        self.runtime.start_failure = "after_open"
        original_write = module._write_journal

        def crash_before_failure_binding(*args, **kwargs):
            if kwargs.get("phase") in {
                "legacy_restored_fenced",
                "handoff_failed_fenced",
            }:
                raise SystemExit("crash after failure receipt before terminal journal")
            return original_write(*args, **kwargs)

        with mock.patch.object(
            module,
            "_write_journal",
            side_effect=crash_before_failure_binding,
        ), self.assertRaises(SystemExit):
            self.apply(receipt)

        journal_path = self.fixture.root / "control" / "writer_handoff_pending.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertNotIn(
            journal["phase"],
            {"legacy_restored_fenced", "handoff_failed_fenced"},
        )
        failure_path = (
            self.fixture.root
            / "audit"
            / "writer-handoff"
            / "failure"
            / f"writer-handoff-failure-{journal['attempt_id']}.json"
        )
        tampered = json.loads(failure_path.read_text(encoding="utf-8"))
        tampered["d_external_open"] = False
        tampered["legacy_rollback"] = {
            "attempted": True,
            "succeeded": True,
            "d_state_restored": True,
            "blocked": False,
        }
        tampered.pop("failure_receipt_sha256")
        tampered["failure_receipt_sha256"] = manifest_sha256(tampered)
        _write_json(failure_path, tampered)

        before_observations = self.runtime.d_external_open_calls
        resolved = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=str(journal["attempt_id"]),
            nonce=NONCE,
            now=lambda: NOW + timedelta(minutes=2),
            allow_test_root=True,
        )
        self.assertFalse(resolved.succeeded)
        self.assertGreater(
            self.runtime.d_external_open_calls,
            before_observations,
        )
        self.assertTrue(self.runtime.open)
        self.assertFalse(self.runtime.legacy_running)
        fenced = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertEqual("handoff_failed_fenced", fenced["phase"])
        self.assertEqual(
            tampered["failure_receipt_sha256"],
            fenced["commit_evidence"]["failure_receipt_sha256"],
        )

    def test_terminal_failure_journal_rejects_fully_resigned_receipt_tamper(
        self,
    ) -> None:
        receipt = self.inspect()
        self.runtime.start_failure = "before_open"
        failed = self.apply(receipt)
        journal_path = self.fixture.root / "control" / "writer_handoff_pending.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertEqual("legacy_restored_fenced", journal["phase"])

        tampered = json.loads(failed.receipt_path.read_text(encoding="utf-8"))
        tampered["legacy_rollback"]["succeeded"] = False
        tampered["legacy_rollback"]["blocked"] = True
        tampered.pop("failure_receipt_sha256")
        tampered["failure_receipt_sha256"] = manifest_sha256(tampered)
        _write_json(failed.receipt_path, tampered)

        before_observations = self.runtime.d_external_open_calls
        with self.assertRaisesRegex(WriterHandoffError, "hash differs from journal"):
            finalize_writer_handoff(
                vm_root=self.fixture.root,
                baseline=self.fixture.baseline,
                runtime=self.runtime,
                attempt_id=str(journal["attempt_id"]),
                nonce=NONCE,
                now=lambda: NOW + timedelta(minutes=2),
                allow_test_root=True,
            )
        self.assertEqual(before_observations, self.runtime.d_external_open_calls)
        self.assertTrue(journal_path.exists())

    def test_d_restore_failure_still_recovers_c_while_journal_fences_d(self) -> None:
        receipt = self.inspect()
        self.runtime.start_failure = "before_open"
        from quant_hub.ops import writer_handoff as module

        original = module._replace_d_state
        calls = 0

        def fail_restore(**arguments):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("fixture D restore failure")
            return original(**arguments)

        with mock.patch(
            "quant_hub.ops.writer_handoff._replace_d_state", side_effect=fail_restore
        ):
            result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.legacy_rollback_succeeded)
        self.assertTrue(self.runtime.legacy_running)
        failure = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        self.assertFalse(failure["legacy_rollback"]["d_state_restored"])
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("legacy_restored_fenced", journal["phase"])

    def test_verified_c_rollback_journal_can_be_atomically_replaced_by_retry(self) -> None:
        first = self.inspect()
        self.runtime.start_failure = "before_open"
        failed = self.apply(first)
        self.assertTrue(failed.legacy_rollback_succeeded)
        self.runtime.start_failure = ""
        retry_nonce = "34" * 24
        retried = inspect_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            nonce=retry_nonce,
            inspected_at=NOW + timedelta(minutes=2),
            allow_test_root=True,
            closure_verifier=self.fixture.closure,
        )
        result = apply_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            inspection_receipt=retried,
            expected_inspection_sha256=manifest_sha256(retried),
            nonce=retry_nonce,
            now=lambda: NOW + timedelta(minutes=3),
            id_factory=lambda: "b" * 32,
            allow_test_root=True,
            closure_verifier=self.fixture.closure,
            legacy_sources=self.fixture.legacy_sources,
        )
        self.assertTrue(result.succeeded)
        self.assertFalse(
            (self.fixture.root / "control" / "writer_handoff_pending.json").exists()
        )

    def test_d_open_or_ambiguous_exposure_permanently_forbids_c_rollback(self) -> None:
        receipt = self.inspect()
        self.runtime.start_failure = "after_open"
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.rollback_blocked)
        self.assertFalse(result.legacy_rollback_attempted)
        self.assertFalse(self.runtime.legacy_running)
        self.assertEqual(0, self.runtime.start_legacy_count)
        failure = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        self.assertTrue(failure["d_external_open"])
        self.assertEqual("d_external_writer_open_rollback_forbidden", failure["error_code"])
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("handoff_failed_fenced", journal["phase"])

    def test_absent_session_key_is_generated_and_success_is_secret_free(self) -> None:
        receipt = self.inspect()
        self.assertFalse((self.fixture.root / "state" / "viewer_secret.key").exists())
        result = self.apply(receipt)
        self.assertTrue(result.succeeded)
        self.assertEqual(SUCCESS_SCHEMA, json.loads(result.receipt_path.read_text(encoding="utf-8"))["schema_version"])
        self.assertEqual("c-comments-final", _value(self.fixture.root / "state" / "comments.sqlite3"))
        self.assertEqual("c-workspace-final", _value(self.fixture.root / "state" / "research_workspace.sqlite3"))
        self.assertFalse((self.fixture.root / "backups").exists())
        self.assertFalse(
            (self.fixture.root / "tmp" / "writer-handoff" / "attempt-fixture").exists()
        )
        self.assertFalse(self.runtime.legacy_running)
        self.assertTrue(self.runtime.open)
        self.assertEqual("running", self.runtime.d_status)
        self.assertEqual(["stop-c", "port-free", "start-d", "probe-d"], self.runtime.events)
        success = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        self.assertTrue(success["writer_transition"]["c_permanently_fenced"])
        self.assertFalse(success["active_authority_changed"])
        key = (self.fixture.root / "state" / "viewer_secret.key").read_text(
            encoding="ascii"
        ).strip()
        self.assertEqual(64, len(key))
        self.assertNotIn(key, json.dumps(success, sort_keys=True))
        self.assertTrue(success["verification"]["session_key_ready"])
        self.assertFalse(
            (self.fixture.root / "control" / "writer_handoff_pending.json").exists()
        )
        self.assertFalse(list((self.fixture.root / "audit" / "writer-handoff" / "failure").glob("*.json")))

    def test_exact_product_shape_copies_state_then_bridges_r0_r1_before_probe(self) -> None:
        successor = ExactSuccessor(
            "release-r1", "e" * 64, "snapshot-r1"
        )

        def exact_closure(root: Path, baseline: V39Baseline):
            value = self.fixture.closure(root, baseline)
            value["authority_status"] = "v2_candidate_pending_bootstrap"
            return value

        def successor_proof(_root: Path, value: ExactSuccessor):
            return {
                "release_id": value.release_id,
                "manifest_sha256": value.manifest_sha256,
                "snapshot_id": value.snapshot_id,
                "authority": "candidate_pending_activation",
            }

        receipt = dict(
            inspect_writer_handoff(
                vm_root=self.fixture.root,
                baseline=self.fixture.baseline,
                successor=successor,
                runtime=self.runtime,
                nonce=NONCE,
                inspected_at=NOW,
                allow_test_root=True,
                closure_verifier=exact_closure,
                successor_verifier=successor_proof,
            )
        )
        original_replace = __import__(
            "quant_hub.ops.writer_handoff", fromlist=["_replace_d_state"]
        )._replace_d_state

        def observed_replace(**arguments):
            self.runtime.events.append("copy-state")
            return original_replace(**arguments)

        with mock.patch(
            "quant_hub.ops.writer_handoff._replace_d_state",
            side_effect=observed_replace,
        ):
            result = self.apply(
                receipt,
                successor=successor,
                closure_verifier=exact_closure,
                successor_verifier=successor_proof,
            )
        self.assertTrue(result.succeeded)
        self.assertLess(
            self.runtime.events.index("stop-c"),
            self.runtime.events.index("copy-state"),
        )
        self.assertLess(
            self.runtime.events.index("copy-state"),
            self.runtime.events.index("bridge-r0-r1"),
        )
        self.assertLess(
            self.runtime.events.index("bridge-r0-r1"),
            self.runtime.events.index("probe-d"),
        )
        self.assertNotIn("start-d", self.runtime.events)
        success = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(successor.release_id, success["release_id"])
        self.assertEqual(successor.manifest_sha256, success["release_manifest_sha256"])
        self.assertTrue(success["active_authority_changed"])

    def test_exact_bridge_failure_before_ingress_restores_c_and_d_state(self) -> None:
        successor = ExactSuccessor(
            "release-r1", "e" * 64, "snapshot-r1"
        )

        def exact_closure(root: Path, baseline: V39Baseline):
            value = self.fixture.closure(root, baseline)
            value["authority_status"] = "v2_candidate_pending_bootstrap"
            return value

        def successor_proof(_root: Path, value: ExactSuccessor):
            return {
                "release_id": value.release_id,
                "manifest_sha256": value.manifest_sha256,
                "snapshot_id": value.snapshot_id,
                "authority": "candidate_pending_activation",
            }

        receipt = dict(
            inspect_writer_handoff(
                vm_root=self.fixture.root,
                baseline=self.fixture.baseline,
                successor=successor,
                runtime=self.runtime,
                nonce=NONCE,
                inspected_at=NOW,
                allow_test_root=True,
                closure_verifier=exact_closure,
                successor_verifier=successor_proof,
            )
        )
        self.runtime.bridge_failure = True
        result = self.apply(
            receipt,
            successor=successor,
            closure_verifier=exact_closure,
            successor_verifier=successor_proof,
        )
        self.assertFalse(result.succeeded)
        self.assertTrue(result.legacy_rollback_succeeded)
        self.assertFalse(result.rollback_blocked)
        self.assertTrue(self.runtime.legacy_running)
        self.assertFalse(self.runtime.open)
        self.assertEqual(
            "d-comments-old",
            _value(self.fixture.root / "state" / "comments.sqlite3"),
        )
        self.assertIn("bridge-r0-r1", self.runtime.events)
        self.assertNotIn("start-d", self.runtime.events)

    def test_missing_session_key_after_d_start_fails_without_c_fallback(self) -> None:
        receipt = self.inspect()
        self.runtime.generate_session_key = False
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.rollback_blocked)
        self.assertFalse(result.writer_authority_committed)
        self.assertFalse(self.runtime.legacy_running)
        self.assertFalse((self.fixture.root / "state" / "viewer_secret.key").exists())

    def test_probe_commit_cut_is_finalized_without_stopping_d(self) -> None:
        receipt = self.inspect()
        with mock.patch(
            "quant_hub.ops.writer_handoff._write_or_verify_success_receipt",
            side_effect=OSError("fixture crash after committed probe"),
        ):
            pending = self.apply(receipt)
        self.assertFalse(pending.succeeded)
        self.assertTrue(pending.writer_authority_committed)
        self.assertEqual("handoff_committed_receipt_pending", pending.error_code)
        self.assertTrue(self.runtime.open)
        self.assertNotIn("stop-d", self.runtime.events)
        journal = json.loads(pending.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual("handoff_committed_receipt_pending", journal["phase"])
        attempt_id = str(journal["attempt_id"])
        success_path = (
            self.fixture.root
            / "audit"
            / "writer-handoff"
            / "success"
            / f"writer-handoff-success-{attempt_id}.json"
        )
        self.assertFalse(success_path.exists())

        completed = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=attempt_id,
            nonce=NONCE,
            now=lambda: NOW + timedelta(minutes=2),
            allow_test_root=True,
        )
        self.assertTrue(completed.succeeded)
        self.assertTrue(success_path.exists())
        self.assertFalse(pending.receipt_path.exists())
        self.assertTrue(self.runtime.open)

    def test_receipt_then_cleanup_cut_and_repeated_finalize_are_idempotent(self) -> None:
        receipt = self.inspect()
        with mock.patch(
            "quant_hub.ops.writer_handoff._remove_journal",
            side_effect=OSError("fixture crash after terminal receipt"),
        ):
            pending = self.apply(receipt)
        self.assertFalse(pending.succeeded)
        self.assertTrue(pending.writer_authority_committed)
        self.assertTrue(self.runtime.open)
        journal = json.loads(pending.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual("handoff_committed_receipt_pending", journal["phase"])
        attempt_id = str(journal["attempt_id"])
        receipt_path = (
            self.fixture.root
            / "audit"
            / "writer-handoff"
            / "success"
            / f"writer-handoff-success-{attempt_id}.json"
        )
        before = receipt_path.read_bytes()
        first = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=attempt_id,
            nonce=NONCE,
            allow_test_root=True,
        )
        second = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=attempt_id,
            nonce=NONCE,
            allow_test_root=True,
        )
        self.assertTrue(first.succeeded)
        self.assertTrue(second.succeeded)
        self.assertEqual(before, receipt_path.read_bytes())
        self.assertTrue(self.runtime.open)
        self.assertNotIn("stop-d", self.runtime.events)

    def test_post_start_probe_failure_does_not_fall_back_to_c(self) -> None:
        receipt = self.inspect()
        self.runtime.probe_ok = False
        result = self.apply(receipt)
        self.assertFalse(result.succeeded)
        self.assertTrue(result.rollback_blocked)
        self.assertFalse(self.runtime.legacy_running)
        self.assertEqual(0, self.runtime.start_legacy_count)

    def test_fresh_finalize_recovers_crash_immediately_after_legacy_stop(self) -> None:
        from quant_hub.ops import writer_handoff as module

        receipt = self.inspect()
        original = module._write_journal

        def crash_before_stopped_phase(*args, **kwargs):
            if kwargs.get("phase") == "legacy_stopped":
                raise SystemExit("crash after legacy stop")
            return original(*args, **kwargs)

        with mock.patch.object(
            module, "_write_journal", side_effect=crash_before_stopped_phase
        ), self.assertRaises(SystemExit):
            self.apply(receipt)
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("legacy_stop_pending", journal["phase"])
        recovered = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=str(journal["attempt_id"]),
            nonce=NONCE,
            now=lambda: NOW + timedelta(minutes=2),
            allow_test_root=True,
        )
        self.assertFalse(recovered.succeeded)
        self.assertTrue(recovered.legacy_rollback_succeeded)
        self.assertTrue(self.runtime.legacy_running)
        self.assertNotIn("bridge-r0-r1", self.runtime.events)

    def test_fresh_finalize_restores_both_d_databases_after_partial_replace_crash(self) -> None:
        from quant_hub.ops import writer_handoff as module

        receipt = self.inspect()
        original_replace = module.os.replace
        replaced_first = False

        def crash_after_first_database(source, destination):
            nonlocal replaced_first
            result = original_replace(source, destination)
            if Path(destination) == self.fixture.root / "state" / "comments.sqlite3":
                replaced_first = True
                raise SystemExit("crash after first D database replace")
            return result

        with mock.patch.object(
            module.os, "replace", side_effect=crash_after_first_database
        ), self.assertRaises(SystemExit):
            self.apply(receipt)
        self.assertTrue(replaced_first)
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("d_state_replace_pending", journal["phase"])
        recovered = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=str(journal["attempt_id"]),
            nonce=NONCE,
            now=lambda: NOW + timedelta(minutes=2),
            allow_test_root=True,
        )
        self.assertTrue(recovered.legacy_rollback_succeeded)
        self.assertEqual(
            "d-comments-old",
            _value(self.fixture.root / "state" / "comments.sqlite3"),
        )
        self.assertEqual(
            "d-workspace-old",
            _value(self.fixture.root / "state" / "research_workspace.sqlite3"),
        )

    def test_fresh_finalize_rejects_self_consistent_checkpoint_aba(self) -> None:
        from quant_hub.ops import writer_handoff as module

        receipt = self.inspect()
        with mock.patch.object(
            module,
            "_replace_d_state",
            side_effect=SystemExit("crash before D state replacement"),
        ), self.assertRaises(SystemExit):
            self.apply(receipt)

        journal_path = self.fixture.root / "control" / "writer_handoff_pending.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        self.assertEqual("d_state_replace_pending", journal["phase"])
        progress = journal["commit_evidence"]
        attempt_id = str(journal["attempt_id"])
        checkpoint_id = str(progress["prehandoff_checkpoint_id"])
        checkpoint_parent = (
            self.fixture.root
            / "tmp"
            / "writer-handoff"
            / attempt_id
            / "checkpoints"
        )
        original = checkpoint_parent / checkpoint_id
        shutil.rmtree(original)
        replacement = create_sqlite_checkpoint(
            sources=self.fixture.legacy_sources,
            checkpoint_root=checkpoint_parent,
            checkpoint_id=checkpoint_id,
            state_authority_id="d-prehandoff",
            captured_under_release_id=self.fixture.baseline.release_id,
            captured_under_manifest_sha256=self.fixture.baseline.manifest_sha256,
            captured_at=NOW + timedelta(minutes=1),
            scratch_root=(
                self.fixture.root
                / "tmp"
                / "writer-handoff"
                / attempt_id
                / "restore-proof"
            ),
            allow_test_root=True,
        )
        self.assertNotEqual(
            progress["prehandoff_checkpoint_manifest_sha256"],
            replacement.manifest_sha256,
        )

        with mock.patch.object(module, "_replace_d_state") as replace, self.assertRaises(
            WriterHandoffError
        ):
            finalize_writer_handoff(
                vm_root=self.fixture.root,
                baseline=self.fixture.baseline,
                runtime=self.runtime,
                attempt_id=attempt_id,
                nonce=NONCE,
                now=lambda: NOW + timedelta(minutes=2),
                allow_test_root=True,
            )
        replace.assert_not_called()
        self.assertTrue(journal_path.exists())

    def _exact_crash_fixture(self):
        successor = ExactSuccessor("release-r1", "e" * 64, "snapshot-r1")

        def exact_closure(root: Path, baseline: V39Baseline):
            value = self.fixture.closure(root, baseline)
            value["authority_status"] = "v2_candidate_pending_bootstrap"
            return value

        def successor_proof(_root: Path, value: ExactSuccessor):
            return {
                "release_id": value.release_id,
                "manifest_sha256": value.manifest_sha256,
                "snapshot_id": value.snapshot_id,
                "authority": "candidate_pending_activation",
            }

        receipt = dict(
            inspect_writer_handoff(
                vm_root=self.fixture.root,
                baseline=self.fixture.baseline,
                successor=successor,
                runtime=self.runtime,
                nonce=NONCE,
                inspected_at=NOW,
                allow_test_root=True,
                closure_verifier=exact_closure,
                successor_verifier=successor_proof,
            )
        )
        return successor, exact_closure, successor_proof, receipt

    def test_fresh_finalize_accepts_exact_r1_open_after_bridge_return_without_replay(self) -> None:
        from quant_hub.ops import writer_handoff as module

        successor, closure, successor_proof, receipt = self._exact_crash_fixture()
        with mock.patch.object(
            module,
            "_verify_committed_surface",
            side_effect=SystemExit("crash after exact bridge opened R1"),
        ), self.assertRaises(SystemExit):
            self.apply(
                receipt,
                successor=successor,
                closure_verifier=closure,
                successor_verifier=successor_proof,
            )
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("d_bridge_pending", journal["phase"])
        self.assertEqual(1, self.runtime.events.count("bridge-r0-r1"))
        completed = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            successor=successor,
            runtime=self.runtime,
            attempt_id=str(journal["attempt_id"]),
            nonce=NONCE,
            now=lambda: NOW + timedelta(minutes=2),
            allow_test_root=True,
        )
        self.assertTrue(completed.succeeded)
        self.assertEqual(1, self.runtime.events.count("bridge-r0-r1"))
        self.assertGreaterEqual(self.runtime.pair_control_checks, 1)

    def test_fresh_finalize_rejects_open_r1_when_prior_pair_proof_is_missing(self) -> None:
        from quant_hub.ops import writer_handoff as module

        successor, closure, successor_proof, receipt = self._exact_crash_fixture()
        with mock.patch.object(
            module,
            "_verify_committed_surface",
            side_effect=SystemExit("crash before exact pair proof"),
        ), self.assertRaises(SystemExit):
            self.apply(
                receipt,
                successor=successor,
                closure_verifier=closure,
                successor_verifier=successor_proof,
            )
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.runtime.pair_control_ok = False
        result = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            successor=successor,
            runtime=self.runtime,
            attempt_id=str(journal["attempt_id"]),
            nonce=NONCE,
            now=lambda: NOW + timedelta(minutes=2),
            allow_test_root=True,
        )
        self.assertFalse(result.succeeded)
        self.assertTrue(result.rollback_blocked)
        self.assertFalse(self.runtime.legacy_running)
        self.assertEqual(1, self.runtime.events.count("bridge-r0-r1"))

    def test_fresh_finalize_recovers_closed_bridge_failure_without_forwarding(self) -> None:
        successor, closure, successor_proof, receipt = self._exact_crash_fixture()
        original_activate = self.runtime.activate_exact_pair
        with mock.patch.object(
            self.runtime,
            "activate_exact_pair",
            side_effect=SystemExit("child controller exited closed"),
        ), self.assertRaises(SystemExit):
            self.apply(
                receipt,
                successor=successor,
                closure_verifier=closure,
                successor_verifier=successor_proof,
            )
        journal = json.loads(
            (self.fixture.root / "control" / "writer_handoff_pending.json").read_text(
                encoding="utf-8"
            )
        )
        self.runtime.activate_exact_pair = original_activate
        self.runtime.bridge_failure = True
        recovered = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            successor=successor,
            runtime=self.runtime,
            attempt_id=str(journal["attempt_id"]),
            nonce=NONCE,
            now=lambda: NOW + timedelta(minutes=2),
            allow_test_root=True,
        )
        self.assertFalse(recovered.succeeded)
        self.assertTrue(recovered.legacy_rollback_succeeded)
        self.assertTrue(self.runtime.legacy_running)
        self.assertFalse(self.runtime.open)

    def test_recovery_crash_after_new_c_pid_does_not_start_second_legacy(self) -> None:
        from quant_hub.ops import writer_handoff as module

        receipt = self.inspect()
        original_write = module._write_journal

        def cut_after_stop(*args, **kwargs):
            if kwargs.get("phase") == "legacy_stopped":
                raise SystemExit("cut after stop")
            return original_write(*args, **kwargs)

        with mock.patch.object(
            module, "_write_journal", side_effect=cut_after_stop
        ), self.assertRaises(SystemExit):
            self.apply(receipt)
        journal_path = self.fixture.root / "control" / "writer_handoff_pending.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        with mock.patch.object(
            module,
            "_failure_receipt",
            side_effect=SystemExit("cut after C restart/verify"),
        ), self.assertRaises(SystemExit):
            finalize_writer_handoff(
                vm_root=self.fixture.root,
                baseline=self.fixture.baseline,
                runtime=self.runtime,
                attempt_id=str(journal["attempt_id"]),
                nonce=NONCE,
                now=lambda: NOW + timedelta(minutes=2),
                allow_test_root=True,
            )
        self.assertEqual(1, self.runtime.start_legacy_count)
        previous = self.runtime.process
        self.runtime.process = LegacyProcess(
            previous.pid + 100,
            previous.executable,
            previous.argv,
            previous.executable_sha256,
            previous.server_sha256,
        )
        recovered = finalize_writer_handoff(
            vm_root=self.fixture.root,
            baseline=self.fixture.baseline,
            runtime=self.runtime,
            attempt_id=str(journal["attempt_id"]),
            nonce=NONCE,
            now=lambda: NOW + timedelta(minutes=3),
            allow_test_root=True,
        )
        self.assertTrue(recovered.legacy_rollback_succeeded)
        self.assertEqual(1, self.runtime.start_legacy_count)

    def test_service_start_allows_only_exact_post_state_install_journal_phase(self) -> None:
        path = self.fixture.root / "control" / "writer_handoff_pending.json"
        active = {
            "release_id": self.fixture.baseline.release_id,
            "manifest_sha256": self.fixture.baseline.manifest_sha256,
        }
        blocked = {
            "schema_version": "qrh-writer-handoff-pending/v4",
            "attempt_id": "handoff-fixture",
            "nonce_sha256": "e" * 64,
            "inspection_sha256": "f" * 64,
            "success_receipt_id": "writer-handoff-success-handoff-fixture",
            **active,
            "phase": "legacy_stop_pending",
            "commit_evidence": None,
            "authority": "coordination_only",
            "legacy_process": self.runtime.process.document(),
        }
        _write_json(path, blocked)
        with self.assertRaises(WindowsServiceError):
            authorize_writer_handoff_service_start(self.fixture.root, active)
        blocked["phase"] = "d_bridge_pending"
        blocked["commit_evidence"] = {
            "final_checkpoint_id": "handoff-final-fixture",
            "final_checkpoint_manifest_sha256": "1" * 64,
            "prehandoff_checkpoint_id": "handoff-pre-d-fixture",
            "prehandoff_checkpoint_manifest_sha256": "2" * 64,
        }
        _write_json(path, blocked)
        authorize_writer_handoff_service_start(self.fixture.root, active)
        blocked["phase"] = "handoff_committed_receipt_pending"
        blocked["commit_evidence"] = {
            "recorded_at": "2026-08-21T04:01:00.000000Z",
            "final_checkpoint_id": "handoff-final-fixture",
            "final_checkpoint_manifest_sha256": "1" * 64,
            "prehandoff_checkpoint_id": "handoff-pre-d-fixture",
            "prehandoff_checkpoint_manifest_sha256": "2" * 64,
        }
        _write_json(path, blocked)
        authorize_writer_handoff_service_start(self.fixture.root, active)


if __name__ == "__main__":
    unittest.main()
