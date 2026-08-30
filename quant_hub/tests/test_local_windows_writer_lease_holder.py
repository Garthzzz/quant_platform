from __future__ import annotations

import copy
from dataclasses import fields
import inspect
import json
import os
from pathlib import Path
import pickle
import subprocess
import sys
import tempfile
import unittest

from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256
from quant_hub.ops import local_windows_writer_lease_holder as holder_module
from quant_hub.ops import local_deployment_persistence as persistence_module
from quant_hub.ops.local_windows_writer_lease_holder import (
    ExactRuntimeLeaseIdentity,
    ProductionWindowsWriterLeaseHolder,
    WindowsWriterLeaseBusy,
    WindowsWriterLeaseHolderError,
)


def _identity(
    *,
    operation: str = "activation",
    role: str = "candidate",
) -> ExactRuntimeLeaseIdentity:
    return ExactRuntimeLeaseIdentity(
        attempt_id="writer-holder-attempt",
        nonce="writer-holder-deployment-nonce",
        operation=operation,
        role=role,
        start_nonce="writer-holder-start-nonce",
        state_identity_sha256="c" * 64,
        release_id="release-r1",
        manifest_sha256="d" * 64,
    )


@unittest.skipUnless(os.name == "nt", "真实 Win32 writer lock 只在 Windows 执行")
class WindowsWriterLeaseHolderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="qrh-writer-holder-", dir=Path.cwd()
        )
        self.root = Path(self.temporary.name).resolve(strict=True)
        (self.root / "state").mkdir()
        (self.root / "tmp" / "service").mkdir(parents=True)
        self.adapter = holder_module._TestOnlyWindowsWriterLeaseHolderAdapter.load()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def acquire(self):
        return self.adapter.acquire(self.root, _identity())

    def test_real_kernel_lock_publishes_canonical_closed_record(self) -> None:
        lease = self.acquire()
        try:
            record = lease.record_document
            raw = (self.root / "state" / "writer_lease.json").read_bytes()
            self.assertEqual(canonical_bytes(record), raw)
            self.assertEqual(identity_sha256({
                key: value
                for key, value in record.items()
                if key != "lease_record_sha256"
            }), record["lease_record_sha256"])
            self.assertEqual(1, record["lease_epoch"])
            self.assertEqual(os.getpid(), record["holder"]["child_pid"])
            self.assertEqual(os.getppid(), record["holder"]["host_pid"])
            self.assertEqual(
                "state/writer_authority.lock", record["lock"]["relative_path"]
            )
            self.assertGreater(record["lock"]["handle_value"], 0)
            self.assertEqual(32, len(record["lock"]["file_id"]))
            self.assertTrue((self.root / "state" / "writer_authority.lock").is_file())
        finally:
            lease.close()

    def test_second_writer_is_rejected_without_overwriting_record(self) -> None:
        first = self.acquire()
        before = (self.root / "state" / "writer_lease.json").read_bytes()
        try:
            with self.assertRaises(WindowsWriterLeaseBusy):
                self.acquire()
            self.assertEqual(
                before, (self.root / "state" / "writer_lease.json").read_bytes()
            )
        finally:
            first.close()

    def test_close_releases_lock_and_next_epoch_is_monotonic(self) -> None:
        first = self.acquire()
        first_record = first.record_document
        first.close()
        with self.assertRaises(WindowsWriterLeaseHolderError):
            _ = first.record_document
        second = self.acquire()
        try:
            second_record = second.record_document
            self.assertEqual(2, second_record["lease_epoch"])
            self.assertNotEqual(
                first_record["lease_nonce"], second_record["lease_nonce"]
            )
            self.assertNotEqual(first_record["lease_id"], second_record["lease_id"])
        finally:
            second.close()

    def test_owner_crash_only_retirement_cannot_close_numeric_handle(self) -> None:
        class _ExactBindingStub:
            @staticmethod
            def _assert_exact_binding() -> None:
                return None

        lease_type = holder_module.LockedWindowsWriterLease
        lease = object.__new__(lease_type)
        object.__setattr__(lease, "_sealed", False)
        object.__setattr__(lease, "_api", _ExactBindingStub())
        object.__setattr__(lease, "_state", "live")
        object.__setattr__(lease, "_handle", 123)
        object.__setattr__(lease, "_sealed", True)

        lease._retire_to_owner_crash_only()

        self.assertEqual("owner_crash_only", lease._state)
        self.assertEqual(0, lease._handle)
        lease._finalize_for_process_exit()
        self.assertEqual("owner_crash_only", lease._state)
        self.assertEqual(0, lease._handle)
        with self.assertRaises(WindowsWriterLeaseHolderError):
            lease.close()

    def test_malformed_previous_record_fails_closed_and_releases_lock(self) -> None:
        first = self.acquire()
        valid = first.record_document
        first.close()
        malformed = copy.deepcopy(valid)
        malformed["lease_epoch"] = True
        malformed.pop("lease_record_sha256")
        malformed["lease_record_sha256"] = identity_sha256(malformed)
        (self.root / "state" / "writer_lease.json").write_bytes(
            canonical_bytes(malformed)
        )
        with self.assertRaises(WindowsWriterLeaseHolderError):
            self.acquire()
        # acquisition failure must have closed the kernel lock.  Restoring the
        # previous canonical record allows an immediate retry in the same process.
        (self.root / "state" / "writer_lease.json").write_bytes(
            canonical_bytes(valid)
        )
        retry = self.acquire()
        try:
            self.assertEqual(2, retry.record_document["lease_epoch"])
        finally:
            retry.close()

    def test_fully_resigned_previous_nested_aliases_are_rejected(self) -> None:
        initial = self.acquire()
        valid = initial.record_document
        initial.close()
        cases = (
            "holder_bool",
            "lock_bool",
            "volume_bool",
            "volume_overflow",
            "file_id",
            "extra",
        )
        expected_epoch = 1
        for case in cases:
            changed = copy.deepcopy(valid)
            if case == "holder_bool":
                changed["holder"]["host_pid"] = True  # type: ignore[index]
                changed["holder"].pop("holder_identity_sha256")  # type: ignore[union-attr]
                changed["holder"]["holder_identity_sha256"] = identity_sha256(  # type: ignore[index]
                    changed["holder"]
                )
            elif case == "lock_bool":
                changed["lock"]["handle_value"] = True  # type: ignore[index]
                changed["lock"].pop("lock_identity_sha256")  # type: ignore[union-attr]
                changed["lock"]["lock_identity_sha256"] = identity_sha256(  # type: ignore[index]
                    changed["lock"]
                )
            elif case in {"volume_bool", "volume_overflow"}:
                changed["lock"]["volume_serial_number"] = (  # type: ignore[index]
                    True if case == "volume_bool" else 1 << 64
                )
                changed["lock"].pop("lock_identity_sha256")  # type: ignore[union-attr]
                changed["lock"]["lock_identity_sha256"] = identity_sha256(  # type: ignore[index]
                    changed["lock"]
                )
            elif case == "file_id":
                changed["lock"]["file_id"] = "ab"  # type: ignore[index]
                changed["lock"].pop("lock_identity_sha256")  # type: ignore[union-attr]
                changed["lock"]["lock_identity_sha256"] = identity_sha256(  # type: ignore[index]
                    changed["lock"]
                )
            else:
                changed["qualified"] = True
            changed.pop("lease_record_sha256")
            changed["lease_record_sha256"] = identity_sha256(changed)
            (self.root / "state" / "writer_lease.json").write_bytes(
                canonical_bytes(changed)
            )
            with self.subTest(case=case), self.assertRaises(
                WindowsWriterLeaseHolderError
            ):
                self.acquire()
            (self.root / "state" / "writer_lease.json").write_bytes(
                canonical_bytes(valid)
            )
            retry = self.acquire()
            expected_epoch += 1
            try:
                valid = retry.record_document
                self.assertEqual(expected_epoch, valid["lease_epoch"])
            finally:
                retry.close()

    def test_previous_volume_serial_accepts_exact_uint64_upper_bound(self) -> None:
        initial = self.acquire()
        changed = initial.record_document
        initial.close()
        changed["lock"]["volume_serial_number"] = (1 << 64) - 1  # type: ignore[index]
        changed["lock"].pop("lock_identity_sha256")  # type: ignore[union-attr]
        changed["lock"]["lock_identity_sha256"] = identity_sha256(  # type: ignore[index]
            changed["lock"]
        )
        changed.pop("lease_record_sha256")
        changed["lease_record_sha256"] = identity_sha256(changed)
        (self.root / "state" / "writer_lease.json").write_bytes(
            canonical_bytes(changed)
        )
        lease = self.acquire()
        try:
            self.assertEqual(2, lease.record_document["lease_epoch"])
        finally:
            lease.close()

    def test_abnormal_child_exit_releases_kernel_lock(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src"
        identity = _identity()
        payload = json.dumps(
            {
                field: getattr(identity, field)
                for field in (item.name for item in fields(identity) if item.init)
            }
        )
        script = (
            "import json,sys\n"
            "sys.path.insert(0,sys.argv[3])\n"
            "from pathlib import Path\n"
            "from quant_hub.ops.local_windows_writer_lease_holder import "
            "ExactRuntimeLeaseIdentity,_TestOnlyWindowsWriterLeaseHolderAdapter\n"
            "i=ExactRuntimeLeaseIdentity(**json.loads(sys.argv[2]))\n"
            "a=_TestOnlyWindowsWriterLeaseHolderAdapter.load()\n"
            "lease=a.acquire(Path(sys.argv[1]),i)\n"
            "print('READY',flush=True)\n"
            "sys.stdin.buffer.read(1)\n"
        )
        environment = {
            **os.environ,
            "PYTHONPATH": str(source_root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "TEMP": str(self.root / "tmp" / "service"),
            "TMP": str(self.root / "tmp" / "service"),
        }
        process = subprocess.Popen(
            (
                sys.executable,
                "-I",
                "-c",
                script,
                str(self.root),
                payload,
                str(source_root),
            ),
            cwd=self.root,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            line = process.stdout.readline() if process.stdout is not None else ""
            if line.strip() != "READY":
                stderr = process.stderr.read() if process.stderr is not None else ""
                self.fail(f"child writer holder 未就绪: {stderr}")
            with self.assertRaises(WindowsWriterLeaseBusy):
                self.acquire()
            process.terminate()
            process.wait(timeout=10)
            recovered = self.acquire()
            try:
                self.assertEqual(2, recovered.record_document["lease_epoch"])
            finally:
                recovered.close()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()

    def test_exact_runtime_identity_rejects_role_and_path_aliases(self) -> None:
        for operation, role in (
            ("bootstrap_first_pair", "candidate"),
            ("activation", "baseline"),
            ("rollback", "baseline"),
        ):
            with self.subTest(operation=operation, role=role), self.assertRaises(
                WindowsWriterLeaseHolderError
            ):
                _identity(operation=operation, role=role)
        values = {
            field: getattr(_identity(), field)
            for field in (
                item.name for item in fields(_identity()) if item.init
            )
        }
        values["release_id"] = r"release-r1\..\release-r1"
        with self.assertRaises(WindowsWriterLeaseHolderError):
            ExactRuntimeLeaseIdentity(**values)
        identity = _identity()
        self.assertEqual(
            r"D:\quant\quant_platform\releases\release-r1",
            identity.release_path,
        )
        self.assertNotEqual("0" * 64, identity.scm_identity_sha256)
        self.assertNotEqual("0" * 64, identity.authorization_sha256)
        self.assertEqual(
            ("exact-runtime", *identity.child_argv[9:]),
            identity.service_start_arguments,
        )

    def test_runtime_identity_derivation_is_exactly_the_b2_start_contract(self) -> None:
        identity = _identity()
        journal = {
            "attempt": identity.attempt_id,
            "nonce": identity.nonce,
            "operation": identity.operation,
            "state_plan": {
                "state_identity_sha256": identity.state_identity_sha256
            },
        }
        start = {
            "role": identity.role,
            "start_nonce": identity.start_nonce,
            "release": {
                "release_id": identity.release_id,
                "release_path": identity.release_path,
                "manifest_sha256": identity.manifest_sha256,
            },
            "scm_identity_sha256": "f" * 64,
        }
        scm = persistence_module._transient_scm_start_plan_sha256(journal, start)
        self.assertEqual(identity.scm_identity_sha256, scm)
        start["scm_identity_sha256"] = scm
        self.assertEqual(
            identity.authorization_sha256,
            persistence_module._transient_start_authorization_sha256(
                journal, start
            ),
        )

    def test_product_surface_has_no_root_or_api_injection(self) -> None:
        self.assertEqual(
            ["self", "identity"],
            list(inspect.signature(
                ProductionWindowsWriterLeaseHolder.acquire_exact_d
            ).parameters),
        )
        self.assertEqual(
            [],
            list(inspect.signature(
                ProductionWindowsWriterLeaseHolder.load_exact_d
            ).parameters),
        )
        self.assertNotIn(
            "_TestOnlyWindowsWriterLeaseHolderAdapter", holder_module.__all__
        )
        production = ProductionWindowsWriterLeaseHolder.load_exact_d()
        with self.assertRaises(TypeError):
            production._api = object()  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            pickle.dumps(production)
        with self.assertRaises(TypeError):
            type("FakeHolder", (ProductionWindowsWriterLeaseHolder,), {})


if __name__ == "__main__":
    unittest.main()
