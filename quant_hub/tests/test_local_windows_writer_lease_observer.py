from __future__ import annotations

from dataclasses import fields
import ctypes
from ctypes import wintypes
import inspect
import json
import os
from pathlib import Path
import pickle
import subprocess
import sys
import tempfile
import unittest

from quant_hub.ops import local_windows_scm_process_observer as scm_module
from quant_hub.ops import local_windows_writer_lease_holder as holder_module
from quant_hub.ops import local_windows_writer_lease_observer as observer_module
from quant_hub.ops.local_windows_writer_lease_holder import (
    ExactRuntimeLeaseIdentity,
)
from quant_hub.ops.local_windows_writer_lease_observer import (
    ProductionWindowsWriterLeaseObserver,
    WindowsWriterLeaseObserverError,
)


def _identity() -> ExactRuntimeLeaseIdentity:
    return ExactRuntimeLeaseIdentity(
        attempt_id="writer-observer-attempt",
        nonce="writer-observer-deployment-nonce",
        operation="activation",
        role="candidate",
        start_nonce="writer-observer-start-nonce",
        state_identity_sha256="c" * 64,
        release_id="release-r1",
        manifest_sha256="d" * 64,
    )


class WindowsWriterLeaseObserverContractTests(unittest.TestCase):
    def test_product_surface_is_exact_and_non_serializable(self) -> None:
        self.assertEqual(
            ["self", "scm", "endpoint"],
            list(
                inspect.signature(
                    ProductionWindowsWriterLeaseObserver.observe
                ).parameters
            ),
        )
        self.assertEqual(
            ["self", "scm", "endpoint"],
            list(
                inspect.signature(
                    ProductionWindowsWriterLeaseObserver.observe_steady
                ).parameters
            ),
        )
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    ProductionWindowsWriterLeaseObserver.load_exact_d
                ).parameters
            ),
        )
        observer = ProductionWindowsWriterLeaseObserver.load_exact_d()
        with self.assertRaises(WindowsWriterLeaseObserverError):
            observer.observe(object(), object())  # type: ignore[arg-type]
        with self.assertRaises(WindowsWriterLeaseObserverError):
            observer.observe_steady(object(), object())  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            observer._api = object()  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            pickle.dumps(observer)
        with self.assertRaises(TypeError):
            type("ForgedObserver", (ProductionWindowsWriterLeaseObserver,), {})
        self.assertNotIn(
            "_ProductionWindowsWriterLeaseObserverApi",
            observer_module.__all__,
        )

    def test_strict_record_parser_rejects_duplicates_nan_and_noncanonical(self) -> None:
        for raw in (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a": 1}',
            b'[]',
            b'\xff',
        ):
            with self.subTest(raw=raw), self.assertRaises(
                WindowsWriterLeaseObserverError
            ):
                observer_module._strict_json(raw)
        self.assertEqual(
            {"a": 1}, observer_module._strict_json(b'{"a":1}')
        )

    def test_scm_child_open_includes_only_required_duplicate_right(self) -> None:
        self.assertEqual(0x0040, scm_module._PROCESS_DUP_HANDLE)
        source = inspect.getsource(
            scm_module._WindowsScmProcessObservationRunner.observe
        )
        self.assertIn("_PROCESS_DUP_HANDLE", source)
        self.assertNotIn("_PROCESS_ALL_ACCESS", source)


@unittest.skipUnless(os.name == "nt", "真实 DuplicateHandle 只在 Windows 执行")
class WindowsWriterLeaseDuplicateIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="qrh-writer-observer-", dir=Path.cwd()
        )
        self.root = Path(self.temporary.name).resolve(strict=True)
        (self.root / "state").mkdir()
        (self.root / "tmp" / "service").mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_real_child_handle_duplicates_to_same_file_and_fences_writer(self) -> None:
        identity = _identity()
        source_root = Path(__file__).resolve().parents[1] / "src"
        payload = json.dumps(
            {
                item.name: getattr(identity, item.name)
                for item in fields(identity)
                if item.init
            }
        )
        script = (
            "import json,sys\n"
            "sys.path.insert(0,sys.argv[3])\n"
            "from pathlib import Path\n"
            "from quant_hub.ops.local_windows_writer_lease_holder import "
            "ExactRuntimeLeaseIdentity,_TestOnlyWindowsWriterLeaseHolderAdapter\n"
            "i=ExactRuntimeLeaseIdentity(**json.loads(sys.argv[2]))\n"
            "lease=_TestOnlyWindowsWriterLeaseHolderAdapter.load().acquire("
            "Path(sys.argv[1]),i)\n"
            "lease._canary_checkpoint()\n"
            "print(json.dumps(lease.record_document,separators=(',',':')),flush=True)\n"
            "sys.stdin.buffer.read(1)\n"
        )
        environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "TEMP": str(self.root / "tmp" / "service"),
            "TMP": str(self.root / "tmp" / "service"),
        }
        child = subprocess.Popen(
            (
                sys._base_executable,
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
        kernel32 = ctypes.WinDLL(
            "kernel32.dll",
            use_last_error=True,
            winmode=observer_module._LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        open_process = kernel32.OpenProcess
        open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        open_process.restype = wintypes.HANDLE
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        process_handle: int | None = None
        duplicate_value: int | None = None
        try:
            line = child.stdout.readline() if child.stdout is not None else ""
            if not line:
                stderr = child.stderr.read() if child.stderr is not None else ""
                self.fail(f"child writer holder 未就绪: {stderr}")
            self.assertIsNone(child.poll())
            record = json.loads(line)
            self.assertEqual(child.pid, record["holder"]["child_pid"])
            api = observer_module._ProductionWindowsWriterLeaseObserverApi.load_exact_d()
            process_handle = open_process(
                scm_module._PROCESS_DUP_HANDLE
                | scm_module._PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                child.pid,
            )
            self.assertIs(type(process_handle), int)
            self.assertGreater(process_handle, 0)
            output = wintypes.HANDLE()
            result = api.duplicate_handle(
                process_handle,
                record["lock"]["handle_value"],
                api.get_current_process(),
                ctypes.byref(output),
                observer_module._GENERIC_READ | observer_module._GENERIC_WRITE,
                False,
                0,
            )
            self.assertEqual(
                1,
                result,
                "DuplicateHandle failed with Windows error "
                f"{ctypes.get_last_error()} for child handle "
                f"{record['lock']['handle_value']}",
            )
            duplicate_value = output.value
            self.assertIs(type(duplicate_value), int)
            observed = observer_module._query_file(
                api,
                duplicate_value,
                expected_path=str(
                    self.root / "state" / "writer_authority.lock"
                ),
            )
            self.assertEqual(
                record["lock"]["volume_serial_number"],
                observed.volume_serial_number,
            )
            self.assertEqual(record["lock"]["file_id"], observed.file_id)
            self.assertTrue(close_handle(duplicate_value))
            duplicate_value = None

            ctypes.set_last_error(0)
            conflict = api.create_file_w(
                str(self.root / "state" / "writer_authority.lock"),
                observer_module._GENERIC_WRITE,
                observer_module._FILE_SHARE_READ,
                None,
                observer_module._OPEN_EXISTING,
                observer_module._FILE_ATTRIBUTE_NORMAL
                | observer_module._FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            self.assertEqual(ctypes.c_void_p(-1).value, conflict)
            self.assertEqual(32, ctypes.get_last_error())

            child.terminate()
            child.wait(timeout=10)
            reopened = api.create_file_w(
                str(self.root / "state" / "writer_authority.lock"),
                observer_module._GENERIC_WRITE,
                observer_module._FILE_SHARE_READ,
                None,
                observer_module._OPEN_EXISTING,
                observer_module._FILE_ATTRIBUTE_NORMAL
                | observer_module._FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            self.assertIs(type(reopened), int)
            self.assertGreater(reopened, 0)
            self.assertTrue(close_handle(reopened))
        finally:
            if duplicate_value is not None:
                close_handle(duplicate_value)
            if process_handle is not None:
                close_handle(process_handle)
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()


if __name__ == "__main__":
    unittest.main()
