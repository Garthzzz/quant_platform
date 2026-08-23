from __future__ import annotations

import hashlib
import json
import base64
from pathlib import Path, PureWindowsPath
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.ops.publish_adapters import (
    ActivationAuthorization,
    CONFIG_SCHEMA,
    CommandResult,
    GitHubExactSHACI,
    HTTPResponse,
    IncrementalVMTransport,
    OpenSSHDeploymentInvoker,
    OpenSSHVMBackend,
    ProductionPublishConfig,
    PublishAdapterError,
    ReleaseFile,
    ReleaseMaterial,
    SecretValue,
    VMDeploymentAdapter,
    _powershell_package_inventory_verification_script,
)
from quant_hub.ops.vm_boundary import validate_production_vm_write_path
from quant_hub.ops.release_identity import manifest_sha256
from quant_hub.ops.windows_service import quant_hub_package_inventory_sha256


COMMIT = "1" * 40
CANDIDATE_HASH = "2" * 64
ROOT = Path(__file__).resolve().parents[2]


class AuthorityPatchedTestCase(unittest.TestCase):
    """Historical downstream behavior below the closed product gate."""

    def setUp(self) -> None:
        authority = patch(
            "quant_hub.ops.publish_adapters.require_failure_domain_authority",
            return_value=None,
        )
        authority.start()
        self.addCleanup(authority.stop)


def config_value() -> dict[str, object]:
    return {
        "schema_version": CONFIG_SCHEMA,
        "github": {
            "owner": "Garthzzz",
            "repository": "quant_platform",
            "workflow_id": 123456,
            "credential_target": "github-actions-read",
            "poll_interval_seconds": 1,
            "timeout_seconds": 10,
        },
        "vm": {
            "ssh_alias": "honghu-vm",
            "target_address": "10.5.1.240",
            "root": r"D:\quant\quant_platform",
        },
    }


def run(run_id: int, *, sha: str = COMMIT, status: str = "completed", conclusion="success"):
    return {
        "id": run_id,
        "workflow_id": 123456,
        "head_sha": sha,
        "head_branch": "main",
        "event": "push",
        "status": status,
        "conclusion": conclusion,
        "repository": {"full_name": "Garthzzz/quant_platform"},
    }


class ProductionConfigTests(unittest.TestCase):
    def test_checked_in_schema_matches_runtime_contract_and_contains_no_secret(self) -> None:
        schema_path = ROOT / "config" / "production_publish.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(
            CONFIG_SCHEMA, schema["properties"]["schema_version"]["const"]
        )
        self.assertEqual(
            r"D:\quant\quant_platform",
            schema["properties"]["vm"]["properties"]["root"]["const"],
        )
        self.assertNotIn("token", schema["properties"]["github"]["properties"])

    def test_config_is_closed_contains_no_secret_and_root_is_exact(self) -> None:
        config = ProductionPublishConfig.parse(config_value())
        self.assertEqual(PureWindowsPath(r"D:\quant\quant_platform"), config.vm.root)
        self.assertEqual("10.5.1.240", config.vm.target_address)
        self.assertEqual("github-actions-read", config.github.credential_target)
        value = config_value()
        value["github"]["token"] = "must-not-be-accepted"
        with self.assertRaisesRegex(PublishAdapterError, "schema is not closed"):
            ProductionPublishConfig.parse(value)

    def test_c_vm_or_same_prefix_sibling_is_rejected_by_vm_boundary(self) -> None:
        for forbidden in (r"C:\quant_platform", r"D:\quant\quant_platform_other"):
            value = config_value()
            value["vm"]["root"] = forbidden
            with self.subTest(root=forbidden), self.assertRaises(PublishAdapterError):
                ProductionPublishConfig.parse(value)

    def test_second_recovery_vm_is_rejected(self) -> None:
        for forbidden in ("10.5.1.223", "10.5.1.235"):
            value = config_value()
            value["vm"]["target_address"] = forbidden
            with self.subTest(address=forbidden), self.assertRaisesRegex(
                PublishAdapterError, "10.5.1.240"
            ):
                ProductionPublishConfig.parse(value)

    def test_secret_value_never_renders_plaintext(self) -> None:
        secret = SecretValue("super-secret-value")
        self.assertEqual("SecretValue(<redacted>)", repr(secret))
        self.assertEqual("SecretValue(<redacted>)", str(secret))
        self.assertNotIn("super-secret-value", repr(secret))


class GitHubExactSHATests(unittest.TestCase):
    def test_only_latest_exact_repo_workflow_main_push_run_is_accepted(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).github
        seen: dict[str, object] = {}

        def get(url, headers, timeout):
            seen.update(url=url, headers=headers, timeout=timeout)
            body = {
                "workflow_runs": [
                    run(9, sha="9" * 40),
                    {**run(10), "workflow_id": 999},
                    run(11),
                ]
            }
            return HTTPResponse(200, json.dumps(body).encode("utf-8"))

        adapter = GitHubExactSHACI(
            config,
            secret_provider=lambda target: SecretValue("protected-token-value"),
            http_get=get,
        )
        result = adapter(COMMIT)
        self.assertEqual(COMMIT, result.commit_sha)
        self.assertEqual("11", result.run_id)
        self.assertIn(f"head_sha={COMMIT}", seen["url"])
        self.assertEqual("Bearer protected-token-value", seen["headers"]["Authorization"])

    def test_failure_and_invalid_json_do_not_echo_body_or_credential(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).github
        for response in (HTTPResponse(403, b"protected-token-value"), HTTPResponse(200, b"no-json")):
            adapter = GitHubExactSHACI(
                config,
                secret_provider=lambda _: SecretValue("protected-token-value"),
                http_get=lambda *_: response,
            )
            with self.subTest(status=response.status), self.assertRaises(PublishAdapterError) as caught:
                adapter(COMMIT)
            self.assertNotIn("protected-token-value", str(caught.exception))

    def test_latest_exact_run_failure_is_not_masked_by_older_success(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).github
        response = HTTPResponse(
            200,
            json.dumps({"workflow_runs": [run(1), run(2, conclusion="failure")]}).encode(),
        )
        adapter = GitHubExactSHACI(
            config,
            secret_provider=lambda _: SecretValue("token"),
            http_get=lambda *_: response,
        )
        with self.assertRaisesRegex(PublishAdapterError, "without success"):
            adapter(COMMIT)


class MemoryVMBackend:
    def __init__(self):
        self.files: dict[str, ReleaseFile] = {}
        self.contents: dict[str, bytes] = {}
        self.paths: list[PureWindowsPath] = []

    def ensure_directory(self, path):
        self.paths.append(validate_production_vm_write_path(path, allow_root=False))

    def inventory(self, path):
        self.paths.append(validate_production_vm_write_path(path, allow_root=False))
        return dict(self.files)

    def upload(self, local_path, remote_path):
        approved = validate_production_vm_write_path(remote_path, allow_root=False)
        self.paths.append(approved)
        data = Path(local_path).read_bytes()
        partial = PureWindowsPath(r"D:\quant\quant_platform\incoming\release-1.partial")
        relative = approved.relative_to(partial).as_posix()
        row = ReleaseFile(relative, len(data), hashlib.sha256(data).hexdigest())
        self.files[relative] = row
        self.contents[relative] = data


class IncrementalTransportTests(AuthorityPatchedTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.source = Path(self.temporary.name).resolve()
        (self.source / "app").mkdir()
        (self.source / "app" / "main.py").write_bytes(b"print('ok')\n")
        release = {
            "schema_version": "qrh-release-manifest/v1",
            "release_id": "release-1",
            "built_at": "2026-08-21T08:00:00+08:00",
            "application": {
                "commit_sha": COMMIT,
                "tracked_tree_sha256": "3" * 64,
                "build_tool_version": "adapter-tests/v1",
            },
            "content": {
                "snapshot_id": "snapshot-release-1",
                "source_inventory_sha256": "4" * 64,
                "ir_sha256": "5" * 64,
                "knowledge_sha256": "6" * 64,
                "search_sha256": "7" * 64,
                "knowledge_enrichment": {"status": "not_applicable"},
            },
            "resources": {"inventory_sha256": "8" * 64},
            "state": {
                "compatibility": {
                    "comments": {"read": [1], "write": [1]},
                    "workspace": {"read": [1], "write": [1]},
                }
            },
            "recovery": {
                "compatibility": {
                    "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                    "restore_protocol_versions": ["qrh-restore/v1"],
                }
            },
        }
        (self.source / "release_manifest.json").write_text(
            json.dumps(release, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.files = tuple(
            ReleaseFile(
                path.relative_to(self.source).as_posix(),
                path.stat().st_size,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            for path in sorted(self.source.rglob("*"))
            if path.is_file()
        )
        self.release_hash = manifest_sha256(release)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def candidate(self):
        return {
            "release": {"release_id": "release-1", "manifest_sha256": self.release_hash},
            "candidate_manifest_sha256": CANDIDATE_HASH,
            "deployment_mode": "activate",
        }

    def test_only_missing_or_changed_files_upload_then_full_inventory_verifies(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        backend = MemoryVMBackend()
        existing = next(row for row in self.files if row.path == "app/main.py")
        backend.files[existing.path] = existing
        material = ReleaseMaterial("release-1", self.release_hash, self.source, self.files)
        adapter = IncrementalVMTransport(
            config, material_resolver=lambda *_: material, backend=backend
        )
        result = adapter(self.candidate())
        self.assertEqual("verified", result.status)
        self.assertEqual({"release_manifest.json"}, set(backend.contents))
        self.assertTrue(
            all(str(path).casefold().startswith(r"d:\quant\quant_platform".casefold()) for path in backend.paths)
        )

    def test_extra_remote_file_fails_closed_and_is_not_deleted(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        backend = MemoryVMBackend()
        backend.files["unexpected.bin"] = ReleaseFile("unexpected.bin", 1, "f" * 64)
        material = ReleaseMaterial("release-1", self.release_hash, self.source, self.files)
        adapter = IncrementalVMTransport(
            config, material_resolver=lambda *_: material, backend=backend
        )
        with self.assertRaisesRegex(PublishAdapterError, "missing or extra"):
            adapter(self.candidate())
        self.assertIn("unexpected.bin", backend.files)

    def test_local_material_drift_blocks_before_upload(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        backend = MemoryVMBackend()
        material = ReleaseMaterial("release-1", self.release_hash, self.source, self.files)
        (self.source / "app" / "main.py").write_bytes(b"changed\n")
        adapter = IncrementalVMTransport(
            config, material_resolver=lambda *_: material, backend=backend
        )
        with self.assertRaisesRegex(PublishAdapterError, "changed after freeze"):
            adapter(self.candidate())
        self.assertFalse(backend.contents)


class FakeInvoker:
    def __init__(self, candidate_hash=CANDIDATE_HASH, *, result_mode="activate"):
        self.candidate_hash = candidate_hash
        self.result_mode = result_mode
        self.called = None

    def invoke(self, **kwargs):
        self.called = kwargs
        return {
            "schema_version": "qrh-vm-deploy-result/v1",
            "release_id": kwargs["release_id"],
            "release_manifest_sha256": kwargs["release_manifest_sha256"],
            "publish_candidate_sha256": self.candidate_hash,
            "status": "activated" if self.result_mode == "activate" else "candidate_validated",
            "evidence_id": (
                "activation-1" if self.result_mode == "activate" else "candidate-validation-1"
            ),
            "evidence_type": (
                "activation_receipt"
                if self.result_mode == "activate"
                else "candidate_validation_event"
            ),
        }


class VMDeploymentAdapterTests(AuthorityPatchedTestCase):
    def test_powershell_inventory_matches_python_and_dependency_tamper_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "quant_hub"
            (package / "ops").mkdir(parents=True)
            dependency = package / "ops" / "deployment.py"
            dependency.write_bytes(b"reviewed dependency\n")
            (package / "__init__.py").write_bytes(b"reviewed package\n")
            expected = quant_hub_package_inventory_sha256(package)
            literal = str(package).replace("'", "''")
            script = (
                "$ErrorActionPreference='Stop';"
                f"$packageFull='{literal}';"
                "$candidate=[pscustomobject]@{"
                f"quant_hub_package_inventory_sha256='{expected}'"
                "};"
                + _powershell_package_inventory_verification_script()
                + "Write-Output 'verified'"
            )
            self.assertNotIn("Get-FileHash", script)
            self.assertIn("[Security.Cryptography.SHA256]::Create()", script)
            self.assertIn("$packageFull=$packageItem.FullName.TrimEnd", script)
            # Make the regression independent of the developer machine: even
            # if the cmdlet exists locally, a shadowing function proves the
            # generated verifier never resolves or calls it.
            execution_script = (
                "function global:Get-FileHash{throw 'Get-FileHash is unavailable'};"
                + script
            )
            parsed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[void][scriptblock]::Create([Console]::In.ReadToEnd())",
                ],
                input=execution_script,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, parsed.returncode, parsed.stderr)
            verified = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    execution_script,
                ],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)
            self.assertEqual("verified", verified.stdout.strip())

            dependency.write_bytes(b"tampered dependency\n")
            rejected = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    execution_script,
                ],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("package_inventory_hash_mismatch", rejected.stderr)

    def test_controller_invocation_is_bound_to_exact_d_root_and_identity(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        invoker = FakeInvoker()
        candidate = {
            "release": {"release_id": "release-1", "manifest_sha256": "a" * 64},
            "candidate_manifest_sha256": CANDIDATE_HASH,
            "deployment_mode": "activate",
        }
        result = VMDeploymentAdapter(
            config,
            invoker=invoker,
            activation_authorization_resolver=lambda *_: ActivationAuthorization(
                "attempt-1", "protection-1"
            ),
        )(candidate)
        self.assertEqual("activated", result.status)
        self.assertEqual("activation_receipt", result.evidence_type)
        self.assertEqual(PureWindowsPath(r"D:\quant\quant_platform"), invoker.called["vm_root"])

    def test_candidate_validation_requires_explicit_candidate_only_mode(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        candidate = {
            "release": {"release_id": "release-1", "manifest_sha256": "a" * 64},
            "candidate_manifest_sha256": CANDIDATE_HASH,
            "deployment_mode": "candidate_only",
        }
        result = VMDeploymentAdapter(
            config, invoker=FakeInvoker(result_mode="candidate_only")
        )(candidate)
        self.assertEqual("candidate_validated", result.status)
        default_candidate = {**candidate, "deployment_mode": "activate"}
        with self.assertRaisesRegex(PublishAdapterError, "requested mode"):
            VMDeploymentAdapter(
                config,
                invoker=FakeInvoker(result_mode="candidate_only"),
                activation_authorization_resolver=lambda *_: ActivationAuthorization(
                    "attempt-1", "protection-1"
                ),
            )(default_candidate)

    def test_controller_identity_mismatch_is_rejected(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        candidate = {
            "release": {"release_id": "release-1", "manifest_sha256": "a" * 64},
            "candidate_manifest_sha256": CANDIDATE_HASH,
            "deployment_mode": "activate",
        }
        with self.assertRaisesRegex(PublishAdapterError, "another identity"):
            VMDeploymentAdapter(
                config,
                invoker=FakeInvoker("3" * 64),
                activation_authorization_resolver=lambda *_: ActivationAuthorization(
                    "attempt-1", "protection-1"
                ),
            )(candidate)

    def test_default_activation_without_recovery_authorization_is_rejected(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        candidate = {
            "release": {"release_id": "release-1", "manifest_sha256": "a" * 64},
            "candidate_manifest_sha256": CANDIDATE_HASH,
            "deployment_mode": "activate",
        }
        with self.assertRaisesRegex(PublishAdapterError, "protection is unavailable"):
            VMDeploymentAdapter(config, invoker=FakeInvoker())(candidate)

    def test_ssh_invoker_uses_fixed_module_and_argv_without_shell(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        calls = []

        def runner(arguments):
            calls.append(list(arguments))
            return CommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "qrh-vm-deploy-result/v1",
                        "release_id": "release-1",
                        "release_manifest_sha256": "a" * 64,
                        "publish_candidate_sha256": CANDIDATE_HASH,
                        "status": "activated",
                        "evidence_id": "activation-1",
                        "evidence_type": "activation_receipt",
                    }
                ),
            )

        value = OpenSSHDeploymentInvoker(config, command_runner=runner).invoke(
            vm_root=config.root,
            release_id="release-1",
            release_manifest_sha256="a" * 64,
            publish_candidate_sha256=CANDIDATE_HASH,
            deployment_mode="activate",
            deployment_attempt_id="attempt-1",
            recovery_protection_receipt_id="protection-1",
        )
        self.assertEqual("release-1", value["release_id"])
        self.assertEqual("ssh", calls[0][0])
        script = base64.b64decode(calls[0][-1]).decode("utf-16le")
        self.assertIn("quant_hub.ops.vm_deploy_cli", script)
        self.assertIn("PYTHONDONTWRITEBYTECODE", script)
        self.assertIn("ReparsePoint", script)
        self.assertIn(r"D:\quant\quant_platform\tooling\python\python.exe", script)
        self.assertIn("deployment_cli_module_sha256", script)
        self.assertIn("package_inventory_hash_mismatch", script)
        self.assertIn("& $python @cli", script)
        self.assertNotIn("& python", script)
        self.assertIn("SSH_CONNECTION", script)
        self.assertLess(script.index("SSH_CONNECTION"), script.index("New-Item"))
        self.assertIn(r"D:\quant\quant_platform\tmp\deployment-cli", script)
        self.assertNotIn("C:\\", script)
        parsed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "[void][scriptblock]::Create([Console]::In.ReadToEnd())"],
            input=script, text=True, capture_output=True, check=False,
        )
        self.assertEqual(0, parsed.returncode, parsed.stderr)


class OpenSSHVMBackendTests(AuthorityPatchedTestCase):
    @staticmethod
    def _script(call) -> str:
        return base64.b64decode(call[-1]).decode("utf-16le")

    def test_remote_scripts_enforce_root_and_reparse_checks_before_writes(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        calls = []

        def runner(arguments):
            calls.append(list(arguments))
            if arguments[0] == "ssh" and "Get-ChildItem" in base64.b64decode(
                arguments[-1]
            ).decode("utf-16le"):
                return CommandResult(0, "[]")
            return CommandResult(0, "")

        backend = OpenSSHVMBackend(config, command_runner=runner)
        target = PureWindowsPath(
            r"D:\quant\quant_platform\incoming\release-1.partial"
        )
        backend.ensure_directory(target)
        self.assertEqual({}, backend.inventory(target))
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary) / "payload.bin"
            local.write_bytes(b"sealed-payload")
            backend.upload(local, target / "payload.bin")
        scripts = [
            self._script(call)
            for call in calls
            if call[0] == "ssh"
        ]
        self.assertTrue(all("D:\\quant\\quant_platform" in script for script in scripts))
        self.assertTrue(all("SSH_CONNECTION" in script for script in scripts))
        self.assertTrue(
            all(
                script.index("SSH_CONNECTION") < script.index("New-Item")
                for script in scripts
                if "New-Item" in script
            )
        )
        self.assertTrue(all("ReparsePoint" in script for script in scripts))
        self.assertTrue(all("root_full_path_differs" in script for script in scripts))
        self.assertTrue(all("root_parent_reparse" in script for script in scripts))
        self.assertTrue(all("C:\\quant_platform" not in script for script in scripts))
        self.assertTrue(all("\\reference\\" not in script.casefold() for script in scripts))
        for script in scripts:
            for write_operation in ("New-Item", "Move-Item", "Remove-Item"):
                if write_operation in script:
                    self.assertLess(
                        script.index("root_parent_reparse"),
                        script.index(write_operation),
                    )
            parsed = subprocess.run(
                [
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "[void][scriptblock]::Create([Console]::In.ReadToEnd())",
                ],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, parsed.returncode, parsed.stderr)
        scp = next(call for call in calls if call[0] == "scp")
        self.assertIn("HostName=10.5.1.240", scp)
        self.assertIn("D:/quant/quant_platform/incoming/", scp[-1])
        self.assertIn(".payload.bin.upload.partial", scp[-1])
        self.assertTrue(any("Get-FileHash" in script and "Move-Item" in script for script in scripts))

    def test_wrong_server_identity_blocks_before_scp_or_remote_write(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        calls = []

        def runner(arguments):
            calls.append(list(arguments))
            if arguments[0] == "ssh":
                script = self._script(arguments)
                self.assertIn("ssh_target_address_differs", script)
                self.assertLess(script.index("SSH_CONNECTION"), script.index("New-Item"))
                return CommandResult(1, "")
            self.fail("SCP must not run after server identity rejection")

        backend = OpenSSHVMBackend(config, command_runner=runner)
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary) / "payload.bin"
            local.write_bytes(b"sealed-payload")
            with self.assertRaisesRegex(PublishAdapterError, "SSH command failed"):
                backend.upload(
                    local,
                    PureWindowsPath(
                        r"D:\quant\quant_platform\incoming\release-1.partial\payload.bin"
                    ),
                )
        self.assertEqual(["ssh"], [call[0] for call in calls])

    def test_d_quant_parent_reparse_fails_before_transport_or_move(self) -> None:
        config = ProductionPublishConfig.parse(config_value()).vm
        calls: list[list[str]] = []

        def runner(arguments):
            call = list(arguments)
            calls.append(call)
            self.assertEqual("ssh", call[0])
            script = self._script(call)
            self.assertIn("root_parent_reparse", script)
            self.assertIn("target_escaped_exact_root", script)
            self.assertIn("Split-Path -Parent $rootCursor", script)
            self.assertLess(
                script.index("root_parent_reparse"), script.index("New-Item")
            )
            self.assertNotIn("Move-Item", script)
            # Fake the remote Get-Item check reporting D:\quant as a junction.
            return CommandResult(1, r"root_parent_reparse:D:\quant")

        backend = OpenSSHVMBackend(config, command_runner=runner)
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary) / "payload.bin"
            local.write_bytes(b"sealed-payload")
            with self.assertRaisesRegex(PublishAdapterError, "SSH command failed"):
                backend.upload(
                    local,
                    PureWindowsPath(
                        r"D:\quant\quant_platform\incoming\release-1.partial\payload.bin"
                    ),
                )
        self.assertEqual(["ssh"], [call[0] for call in calls])
        self.assertFalse(any(call[0] == "scp" for call in calls))


if __name__ == "__main__":
    unittest.main()
