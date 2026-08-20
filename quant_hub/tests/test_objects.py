from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import os
from pathlib import Path
import subprocess
from unittest import mock

from quant_hub.ids import sha256_hex
from quant_hub.platform.objects import ObjectCorruptionError, ObjectStore, ObjectStoreError
from tests.helpers import SettingsTestCase


def _object_process_worker(root: str, payload: bytes, queue) -> None:
    try:
        item = ObjectStore(Path(root)).put_bytes(payload)
        queue.put({"created": item.created, "object_id": item.object_id})
    except BaseException as error:
        queue.put({"error": f"{type(error).__name__}: {error}"})


class ObjectStoreTests(SettingsTestCase):
    def test_put_is_atomic_and_idempotent(self) -> None:
        store = ObjectStore(self.settings.object_root)
        payload = b"immutable-object\x00" * 128
        first = store.put_bytes(payload)
        second = store.put_bytes(payload)
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(first.object_id, second.object_id)
        self.assertEqual(payload, store.read_bytes(first.object_id))

    def test_concurrent_first_write_has_one_creator(self) -> None:
        store = ObjectStore(self.settings.object_root)
        payload = b"concurrent" * 4096
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: store.put_bytes(payload), range(16)))
        self.assertEqual(1, sum(item.created for item in results))
        self.assertEqual(1, len({item.object_id for item in results}))

    def test_spawn_processes_atomically_finalize_one_object(self) -> None:
        context = multiprocessing.get_context("spawn")
        queue = context.Queue()
        payload = b"spawn-process-object" * 4096
        processes = [
            context.Process(
                target=_object_process_worker,
                args=(str(self.settings.object_root), payload, queue),
            )
            for _ in range(8)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(20)
            self.assertFalse(process.is_alive(), f"worker did not exit: {process.pid}")
            self.assertEqual(0, process.exitcode)
        results = [queue.get(timeout=2) for _ in processes]
        self.assertFalse([item for item in results if "error" in item], results)
        self.assertEqual(1, sum(bool(item["created"]) for item in results))
        self.assertEqual(1, len({item["object_id"] for item in results}))

    def test_existing_corruption_is_never_overwritten(self) -> None:
        store = ObjectStore(self.settings.object_root)
        payload = b"expected"
        digest = sha256_hex(payload)
        target = self.settings.object_root / store.relative_path(digest)
        target.parent.mkdir(parents=True)
        target.write_bytes(b"corrupt")
        with self.assertRaises(ObjectCorruptionError):
            store.put_bytes(payload)
        self.assertEqual(b"corrupt", target.read_bytes())

    def test_invalid_object_id_is_rejected_before_path_access(self) -> None:
        store = ObjectStore(self.settings.object_root)
        with self.assertRaises(ValueError):
            store.read_bytes("obj_sha256_short")

    def test_read_returns_the_same_bytes_that_were_verified(self) -> None:
        store = ObjectStore(self.settings.object_root)
        payload = b"verify-and-return-once"
        stored = store.put_bytes(payload)
        target = self.settings.object_root / stored.relative_path
        real_read_bytes = Path.read_bytes
        target_reads = 0

        def changing_read(path: Path) -> bytes:
            nonlocal target_reads
            if path == target:
                target_reads += 1
                return payload if target_reads == 1 else b"changed-after-verification"
            return real_read_bytes(path)

        with mock.patch.object(Path, "read_bytes", new=changing_read):
            self.assertEqual(payload, store.read_bytes(stored.object_id))
        self.assertEqual(1, target_reads)

    def test_real_windows_junction_object_root_is_rejected(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows runtime contract")
        external = self.root / "external-objects"
        external.mkdir()
        junction = self.var / "junction-objects"
        junction.parent.mkdir(parents=True)
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
        try:
            with self.assertRaisesRegex(ObjectStoreError, "reparse"):
                ObjectStore(junction).put_bytes(b"must-not-write-through-junction")
            self.assertEqual([], list(external.iterdir()))
        finally:
            if os.path.lexists(junction):
                os.rmdir(junction)

    def test_real_windows_junction_shard_is_rejected_before_write(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows runtime contract")
        store = ObjectStore(self.settings.object_root)
        store.root.mkdir(parents=True)
        payload = b"must-not-write-through-shard-junction"
        digest = sha256_hex(payload)
        shard = store.root / digest[:2]
        external = self.root / "external-shard"
        external.mkdir()
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(shard), str(external)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
        try:
            with self.assertRaisesRegex(ObjectStoreError, "reparse"):
                store.put_bytes(payload)
            self.assertEqual([], list(external.iterdir()))
        finally:
            if os.path.lexists(shard):
                os.rmdir(shard)
