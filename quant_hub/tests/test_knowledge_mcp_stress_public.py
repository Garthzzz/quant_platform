"""Public synthetic pressure tests for the read-only knowledge MCP runtime."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import gc
import hashlib
from io import StringIO
import json
import multiprocessing
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge.contracts import canonical_json
from quant_hub.knowledge_mcp.mirror import (
    AuthorityIdentity,
    MirrorError,
    MirrorSnapshot,
    MirrorStore,
    build_search_artifact,
)
import quant_hub.knowledge_mcp.mirror as mirror_module
from quant_hub.knowledge_mcp.server import StdioMCPServer
from quant_hub.knowledge_mcp.service import (
    KnowledgeMCPService,
    Resolution,
)
from quant_hub.ops.release_identity import manifest_sha256


_HASHES = {
    name: str(index) * 64
    for index, name in enumerate(
        ("tree", "source", "ir", "knowledge", "resources"), 1
    )
}


def _release(release_id: str, snapshot_id: str, artifact: bytes) -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": release_id,
        "built_at": "2026-08-22T08:00:00+08:00",
        "application": {
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": _HASHES["tree"],
            "build_tool_version": "public-mcp-stress/v1",
        },
        "content": {
            "snapshot_id": snapshot_id,
            "source_inventory_sha256": _HASHES["source"],
            "ir_sha256": _HASHES["ir"],
            "knowledge_sha256": _HASHES["knowledge"],
            "search_sha256": hashlib.sha256(artifact).hexdigest(),
            "knowledge_enrichment": {"status": "pending"},
        },
        "resources": {"inventory_sha256": _HASHES["resources"]},
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


def _write_release(
    release_root: Path, release: dict[str, object], artifact: bytes
) -> AuthorityIdentity:
    target = release_root / str(release["release_id"])
    (target / "content").mkdir(parents=True)
    (target / "release_manifest.json").write_text(
        canonical_json(release), encoding="utf-8", newline=""
    )
    (target / "content" / "mcp_search.json").write_bytes(artifact)
    return AuthorityIdentity(
        release_id=str(release["release_id"]),
        manifest_sha256=manifest_sha256(release),
        snapshot_id=str(release["content"]["snapshot_id"]),  # type: ignore[index]
    )


def _build_releases(root: Path, count: int = 3) -> tuple[Path, list[AuthorityIdentity]]:
    intake = root / "synthetic-intake"
    releases = root / "synthetic-releases"
    intake.mkdir()
    releases.mkdir()
    source = intake / "factor.md"
    previous = None
    identities: list[AuthorityIdentity] = []
    for index in range(count):
        source.write_text(
            "# Synthetic leakage controls\n\n"
            + "\n\n".join(
                f"## Revision {member}\n\nUse temporal split {member}."
                for member in range(index + 1)
            )
            + "\n",
            encoding="utf-8",
        )
        compiled = ReferenceCompiler(max_chunk_bytes=180).compile(
            intake, previous=previous
        )
        assert compiled.candidate_snapshot is not None
        previous = compiled.candidate_snapshot
        artifact = build_search_artifact(previous)
        release = _release(f"synthetic-r{index}", previous.snapshot_id, artifact)
        identities.append(_write_release(releases, release, artifact))
    return releases, identities


def _sync_worker(
    mirror_root: str, release_root: str, identity: dict[str, str]
) -> str:
    snapshot = MirrorStore(Path(mirror_root)).sync_from(
        AuthorityIdentity(**identity), Path(release_root)
    )
    return snapshot.identity.release_id


def _exit_holding_lock(mirror_root: str) -> None:
    store = MirrorStore(Path(mirror_root))
    with store._locked():
        os._exit(73)


def _exit_after_empty_lock_create(mirror_root: str) -> None:
    root = Path(mirror_root)
    root.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(root / ".mirror.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL)
    os.close(descriptor)
    os._exit(77)


def _exit_after_pending(
    mirror_root: str, release_root: str, identity: dict[str, str]
) -> None:
    target = AuthorityIdentity(**identity)
    store = MirrorStore(Path(mirror_root))
    original = store._write_pointer

    def cut(value: AuthorityIdentity) -> None:
        if value == target:
            os._exit(74)
        original(value)

    store._write_pointer = cut  # type: ignore[method-assign]
    store.sync_from(target, Path(release_root))


class _NoCallService:
    def startup_probe(self) -> None:
        return None

    def __getattr__(self, name: str):
        raise AssertionError(f"invalid input reached service method {name}")


class _SecretErrorService:
    def search_quant_knowledge(self, **_arguments: object) -> object:
        raise ValueError("Authorization: Bearer synthetic-secret-marker")


class _InvalidUtf8Text:
    def readline(self, _limit: int = -1) -> str:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")


class _FakeIndex:
    def __init__(self, cards: list[SimpleNamespace]) -> None:
        self.cards = cards
        self.limits: list[int] = []

    def search(self, _query: str, *, limit: int, **_kwargs: object) -> SimpleNamespace:
        self.limits.append(limit)
        return SimpleNamespace(
            cards=self.cards[:limit],
            index_version="public-stub/v1",
            total_candidates=100_000,
            no_answer_reason=None,
        )


class _SnapshotStore:
    def __init__(self, previous: MirrorSnapshot) -> None:
        self.previous = previous

    def find_snapshot(self, snapshot_id: str) -> MirrorSnapshot | None:
        return self.previous if snapshot_id == self.previous.identity.snapshot_id else None

    def acknowledge_transition(self, *_args: object) -> None:
        return None


def _card(index: int) -> SimpleNamespace:
    return SimpleNamespace(
        evidence_id=f"evidence-{index}",
        document_id=f"document-{index}",
        document_version_id=f"version-{index}",
        research_id=f"research-{index}",
        title=f"Synthetic {index}",
        heading_path=("Synthetic",),
        text=f"Bounded synthetic evidence {index}",
        locator=SimpleNamespace(
            span_id=f"span-{index}",
            source_sha256="f" * 64,
            line_start=1,
            line_end=1,
            byte_start=0,
            byte_end=8,
        ),
        covered_span_ids=(f"span-{index}",),
        citation_ids=(),
        source_kind="chunk",
        knowledge_kind=None,
        canonical_key=f"canonical-{index}",
        fact_status="source_explicit",
        knowledge_enrichment="pending",
        applicability=None,
        applicability_matches=(),
        limitations=(),
        failures=(),
        applicability_conflicts=(),
        hit_reasons=("synthetic",),
        score=1.0 - index / 100.0,
        rank=index + 1,
        active_status="active",
    )


def _resolution(snapshot: MirrorSnapshot) -> Resolution:
    return Resolution(
        availability="fresh",
        mirror=snapshot,
        local_identity=snapshot.identity,
        observed_identity=snapshot.identity,
        verified_at="2026-08-22T08:00:00+00:00",
        last_verified_at="2026-08-22T08:00:00+00:00",
        reason=None,
    )


def _search_fixture(record_count: int = 100_000):
    identity = AuthorityIdentity("synthetic", "f" * 64, "synthetic-snapshot")
    snapshot = MirrorSnapshot(
        root=Path("synthetic"),
        identity=identity,
        synced_at="2026-08-22T08:00:00+00:00",
        artifact={
            "schema_version": "qrh-mcp-search-artifact/v2",
            "retrieval": {"records": [None] * record_count},
            "knowledge": [],
        },
    )
    service = KnowledgeMCPService(
        store=SimpleNamespace(), authority=SimpleNamespace(), artifact_release_root=None
    )
    index = _FakeIndex([_card(member) for member in range(4)])
    return service, snapshot, index


class KnowledgeMCPPublicStressTests(unittest.TestCase):
    def test_runtime_limits_are_closed_before_service_dispatch(self) -> None:
        server = StdioMCPServer(_NoCallService())  # type: ignore[arg-type]
        deep: object = "x"
        for _ in range(40):
            deep = [deep]
        invalid_arguments = (
            ("search_quant_knowledge", {"query": "x" * 501}),
            ("search_quant_knowledge", {"query": "x", "cursor": "x" * 4097}),
            (
                "search_quant_knowledge",
                {"query": "x", "task_context": {"market": "x" * 17_000}},
            ),
            (
                "search_quant_knowledge",
                {"query": "x", "task_context": {"market": deep}},
            ),
            ("search_quant_knowledge", {"query": "x", "unknown": True}),
            ("get_quant_knowledge", {"object_id": "x" * 201}),
            ("list_knowledge_updates", {"from_snapshot_id": "x" * 201}),
        )
        for index, (name, arguments) in enumerate(invalid_arguments):
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
            )
            self.assertTrue(response["result"]["isError"])  # type: ignore[index]

        oversized = StringIO("{" + "x" * (256 * 1024) + "}\n")
        output = StringIO()
        self.assertEqual(0, server.serve(oversized, output))
        response = json.loads(output.getvalue())
        self.assertEqual(-32600, response["error"]["code"])

    def test_search_requests_only_one_bounded_page(self) -> None:
        service, snapshot, index = _search_fixture()
        with (
            patch.object(service, "_resolve", return_value=_resolution(snapshot)),
            patch.object(service, "_index_for", return_value=index),
        ):
            response = service.search_quant_knowledge(query="bounded", limit=3)
        self.assertEqual([4], index.limits)
        self.assertEqual(3, len(response["results"]))
        self.assertTrue(response["truncated"])
        self.assertIsNotNone(response["continuation"])

        with (
            patch.object(service, "_resolve", return_value=_resolution(snapshot)),
            patch.object(service, "_index_for", return_value=index),
        ):
            second = service.search_quant_knowledge(
                query="bounded",
                limit=3,
                cursor=response["continuation"],
            )
        self.assertEqual([4, 7], index.limits)
        self.assertEqual(["evidence-3"], [row["object_id"] for row in second["results"]])
        self.assertFalse(second["truncated"])

        forged = service._cursor(
            identity=snapshot.identity,
            tool="search_quant_knowledge",
            position=99_999,
            request_hash=hashlib.sha256(
                canonical_json(
                    {
                        "query": "bounded",
                        "task_context": {},
                        "detail": "compact",
                        "include_history": False,
                        "include_conflicts": False,
                    }
                ).encode()
            ).hexdigest(),
        )
        with (
            patch.object(service, "_resolve", return_value=_resolution(snapshot)),
            patch.object(service, "_index_for", return_value=index),
        ):
            rejected = service.search_quant_knowledge(
                query="bounded", limit=3, cursor=forged
            )
        self.assertEqual("continuation_invalid", rejected["status"])
        self.assertEqual([4, 7], index.limits)

    def test_record_scale_matrix_keeps_limit_three_bounded(self) -> None:
        for record_count in (100, 1_000, 10_000, 100_000):
            service, snapshot, index = _search_fixture(record_count)
            service._resolve = (  # type: ignore[method-assign]
                lambda **_kwargs: _resolution(snapshot)
            )
            service._index_for = lambda _mirror: index  # type: ignore[method-assign]
            try:
                for _ in range(1_000):
                    response = service.search_quant_knowledge(
                        query="bounded", limit=3
                    )
                    self.assertEqual(3, len(response["results"]))
            finally:
                service.close()
            self.assertEqual({4}, set(index.limits))

    def test_1000_hot_queries_do_not_accumulate_result_state(self) -> None:
        service, snapshot, index = _search_fixture()
        service._resolve = lambda **_kwargs: _resolution(snapshot)  # type: ignore[method-assign]
        service._index_for = lambda _mirror: index  # type: ignore[method-assign]
        try:
            tracemalloc.start()
            for _ in range(100):
                service.search_quant_knowledge(query="bounded", limit=3)
            index.limits.clear()
            gc.collect()
            before = tracemalloc.get_traced_memory()[0]
            for _ in range(1_000):
                response = service.search_quant_knowledge(query="bounded", limit=3)
                self.assertEqual(3, len(response["results"]))
            gc.collect()
            after = tracemalloc.get_traced_memory()[0]
            tracemalloc.stop()
        finally:
            service.close()
        self.assertEqual({4}, set(index.limits))
        self.assertLess(after - before, 256 * 1024)

    def test_update_diff_keeps_only_bounded_sorted_window(self) -> None:
        identity0 = AuthorityIdentity("r0", "0" * 64, "s0")
        identity1 = AuthorityIdentity("r1", "1" * 64, "s1")
        previous = MirrorSnapshot(
            Path("old"), identity0, "2026-08-22T00:00:00+00:00",
            {"documents": [], "versions": [], "knowledge": []},
        )
        current = MirrorSnapshot(
            Path("new"), identity1, "2026-08-22T00:00:00+00:00",
            {
                "documents": [
                    {
                        "document_id": f"document-{index:06d}",
                        "active_version_id": f"version-{index:06d}",
                        "status": "active",
                        "replacement_document_id": None,
                    }
                    for index in range(100_000)
                ],
                "versions": [],
                "knowledge": [],
            },
        )
        service = KnowledgeMCPService(
            store=_SnapshotStore(previous),
            authority=SimpleNamespace(),
            artifact_release_root=None,
        )
        tracemalloc.start()
        with patch.object(service, "_resolve", return_value=_resolution(current)):
            response = service.list_knowledge_updates(
                from_snapshot_id="s0", limit=3, budget_chars=50_000
            )
            second = service.list_knowledge_updates(
                from_snapshot_id="s0",
                limit=3,
                budget_chars=50_000,
                cursor=response["continuation"],
            )
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(100_000, response["update_count"])
        self.assertEqual(3, len(response["updates"]))
        self.assertEqual(
            ["document-000000", "document-000001", "document-000002"],
            [row["document_id"] for row in response["updates"]],
        )
        self.assertEqual(100_000, second["update_count"])
        self.assertEqual(
            ["document-000003", "document-000004", "document-000005"],
            [row["document_id"] for row in second["updates"]],
        )
        self.assertLess(peak, 4 * 1024 * 1024)

    def test_stdio_and_jsonrpc_fail_closed_without_error_echo(self) -> None:
        output = StringIO()
        self.assertEqual(
            0,
            StdioMCPServer(_NoCallService()).serve(  # type: ignore[arg-type]
                _InvalidUtf8Text(), output
            ),
        )
        self.assertEqual(-32700, json.loads(output.getvalue())["error"]["code"])

        server = StdioMCPServer(_SecretErrorService())  # type: ignore[arg-type]
        invalid_id = server.handle(
            {"jsonrpc": "2.0", "id": [], "method": "ping"}
        )
        self.assertEqual(-32600, invalid_id["error"]["code"])  # type: ignore[index]
        explicit_null = server.handle(
            {"jsonrpc": "2.0", "id": None, "method": "ping", "params": {}}
        )
        self.assertIsNotNone(explicit_null)
        self.assertIsNone(explicit_null["id"])  # type: ignore[index]
        for method, params in (
            ("initialize", 7),
            ("ping", {"unknown": True}),
            ("tools/list", {"unknown": True}),
        ):
            with self.subTest(method=method):
                rejected_shell = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": method,
                        "params": params,
                    }
                )
                self.assertEqual(
                    -32602, rejected_shell["error"]["code"]  # type: ignore[index]
                )
        unknown_param = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "search_quant_knowledge",
                    "arguments": {"query": "bounded"},
                    "unknown": True,
                },
            }
        )
        self.assertEqual(-32602, unknown_param["error"]["code"])  # type: ignore[index]
        redacted = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "search_quant_knowledge",
                    "arguments": {"query": "bounded"},
                },
            }
        )
        encoded = canonical_json(redacted)
        self.assertNotIn("synthetic-secret-marker", encoded)
        self.assertIn("Invalid tool arguments or request state", encoded)

    def test_mirror_lock_matrix_and_crash_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases, identities = _build_releases(root)
            mirror = root / "mirror"
            store = MirrorStore(mirror)
            store.sync_from(identities[0], releases)
            self.assertEqual(b"", store.lock_path.read_bytes())

            context = multiprocessing.get_context("spawn")
            for process_count in (2, 8, 32):
                targets = [identities[1 + member % 2] for member in range(process_count)]
                with ProcessPoolExecutor(
                    max_workers=process_count, mp_context=context
                ) as executor:
                    results = list(
                        executor.map(
                            _sync_worker,
                            [str(mirror)] * process_count,
                            [str(releases)] * process_count,
                            [target.to_dict() for target in targets],
                        )
                    )
                self.assertEqual(process_count, len(results))
                current, pending = store.current_and_pending()
                assert current is not None
                if pending is not None:
                    self.assertEqual(current.identity, pending.to_identity)
                    store.acknowledge_transition(
                        pending.from_identity, pending.to_identity
                    )

            process = context.Process(target=_exit_holding_lock, args=(str(mirror),))
            process.start()
            process.join(30)
            self.assertEqual(73, process.exitcode)
            self.assertIsNotNone(store.current_and_pending()[0])

            current, pending = store.current_and_pending()
            assert current is not None
            if pending is not None:
                store.acknowledge_transition(pending.from_identity, pending.to_identity)
                current = store.current()
                assert current is not None
            target = next(identity for identity in identities if identity != current.identity)
            process = context.Process(
                target=_exit_after_pending,
                args=(str(mirror), str(releases), target.to_dict()),
            )
            process.start()
            process.join(30)
            self.assertEqual(74, process.exitcode)
            resumed = store.sync_from(target, releases)
            self.assertEqual(target, resumed.identity)
            _, pending = store.current_and_pending()
            assert pending is not None
            self.assertEqual(target, pending.to_identity)

    def test_empty_lock_initialization_cut_recovers_without_writing_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mirror = Path(temporary) / "mirror"
            context = multiprocessing.get_context("spawn")
            process = context.Process(
                target=_exit_after_empty_lock_create, args=(str(mirror),)
            )
            process.start()
            process.join(30)
            self.assertEqual(77, process.exitcode)
            store = MirrorStore(mirror)
            store.initialize()
            self.assertEqual(b"", store.lock_path.read_bytes())

            external = Path(temporary) / "external-after-validation.lock"
            real_validate = mirror_module._validate_open_regular_file
            calls = 0

            def insert_hardlink(path: Path, descriptor: int) -> None:
                nonlocal calls
                real_validate(path, descriptor)
                calls += 1
                if calls == 1:
                    os.link(path, external)

            with (
                patch.object(
                    mirror_module,
                    "_validate_open_regular_file",
                    side_effect=insert_hardlink,
                ),
                self.assertRaises(Exception),
            ):
                store.initialize()
            self.assertEqual(b"", external.read_bytes())

    def test_atomic_pointer_retries_transient_sharing_violation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MirrorStore(Path(temporary) / "mirror")
            store.initialize()
            real_replace = os.replace
            calls = 0

            def transient(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls <= 2:
                    raise PermissionError(13, "synthetic sharing violation")
                real_replace(source, destination)

            with patch.object(mirror_module.os, "replace", side_effect=transient):
                store._atomic_json(store.current_path, {"synthetic": True})
            self.assertEqual(3, calls)
            self.assertEqual({"synthetic": True}, json.loads(store.current_path.read_text()))

    def test_lock_links_and_failed_atomic_writes_never_escape_or_accumulate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            external = root / "external.lock"
            external.write_bytes(b"")
            mirror = root / "mirror"
            mirror.mkdir()
            lock_path = mirror / ".mirror.lock"
            os.link(external, lock_path)
            with self.assertRaises(Exception):
                MirrorStore(mirror).initialize()
            self.assertEqual(b"", external.read_bytes())

        with tempfile.TemporaryDirectory() as temporary:
            store = MirrorStore(Path(temporary) / "mirror")
            store.initialize()
            for _ in range(2):
                with (
                    patch.object(
                        mirror_module,
                        "_replace_with_retry",
                        side_effect=PermissionError("persistent sharing refusal"),
                    ),
                    self.assertRaises(PermissionError),
                ):
                    store._atomic_json(store.current_path, {"synthetic": True})
                self.assertFalse((store.root / ".current.json.partial").exists())

    def test_release_partial_is_single_and_same_identity_retry_resumes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases, identities = _build_releases(root, count=2)
            store = MirrorStore(root / "mirror")
            real_replace = mirror_module._replace_with_retry

            def refuse_release(source: Path, destination: Path) -> None:
                if source.is_dir():
                    raise PermissionError("persistent synthetic release sharing refusal")
                real_replace(source, destination)

            with (
                patch.object(
                    mirror_module,
                    "_replace_with_retry",
                    side_effect=refuse_release,
                ),
                self.assertRaises(PermissionError),
            ):
                store.sync_from(identities[0], releases)
            partials = tuple(store.releases_root.glob(".*.partial"))
            self.assertEqual(1, len(partials))

            with self.assertRaisesRegex(MirrorError, "another interrupted"):
                store.sync_from(identities[1], releases)
            self.assertEqual(partials, tuple(store.releases_root.glob(".*.partial")))

            recovered = store.sync_from(identities[0], releases)
            self.assertEqual(identities[0], recovered.identity)
            self.assertEqual((), tuple(store.releases_root.glob(".*.partial")))


if __name__ == "__main__":
    unittest.main()
