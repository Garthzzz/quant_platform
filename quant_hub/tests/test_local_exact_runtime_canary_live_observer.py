from __future__ import annotations

from contextlib import closing
import inspect
import os
from pathlib import Path
import pickle
import sqlite3
import unittest
from unittest import mock

from quant_hub.ops import local_exact_runtime_canary_live_observer as observer
from quant_hub.ops.local_exact_runtime_canary_evidence import (
    ExactRuntimeCanaryRequest,
)
from quant_hub.ops.local_exact_runtime_canary_input import (
    LockedExactRuntimeCanaryInput,
)
from quant_hub.ops.local_exact_runtime_canary_observer import (
    ExactRuntimeCanaryHttpResponse,
    ExactRuntimeCanaryTransportError,
    ProductionExactRuntimeCanaryTransport,
)
from quant_hub.ops.local_exact_runtime_controller_tooling_observer import (
    LockedExactRuntimeControllerToolingObservation,
    ProductionExactRuntimeControllerToolingObserver,
)
from quant_hub.ops.local_windows_endpoint_observer import (
    LockedWindowsEndpointObservation,
)
from quant_hub.ops.local_windows_scm_process_observer import (
    LockedWindowsScmProcessObservation,
)
from quant_hub.ops.local_windows_writer_lease_observer import (
    LockedWindowsWriterLeaseObservation,
)
from tests.test_local_exact_runtime_canary_runner import (
    ExactRuntimeCanaryRunnerTests as RunnerFixture,
)


RunnerFixture.__test__ = False


class _ToolingCoreProbe:
    def __init__(self, *, fail_close: bool = False) -> None:
        self.closed = False
        self._state = "live"
        self.fail_close = fail_close

    def close(self) -> None:
        if self.fail_close:
            self._state = "owner_crash_only"
            raise observer.ExactRuntimeControllerToolingObserverError(
                "fixture close outcome unknown"
            )
        self.closed = True
        self._state = "closed"


class _WorkspaceCloseProbe:
    def __init__(self) -> None:
        self.released = False

    def _close_runtime_canary_input_public(self, canary) -> None:
        canary._close_from_workspace(self)

    def _release_runtime_canary_input(self, canary) -> None:
        del canary
        self.released = True


class ExactRuntimeCanaryLiveObserverContractTests(unittest.TestCase):
    def test_product_surface_is_fixed_exact_sealed_and_non_serializable(self) -> None:
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    observer.ProductionExactRuntimeCanaryLiveObserver.load_exact_d
                ).parameters
            ),
        )
        self.assertEqual(
            ["self", "canary", "scm", "endpoint", "writer"],
            list(
                inspect.signature(
                    observer.ProductionExactRuntimeCanaryLiveObserver.observe
                ).parameters
            ),
        )
        product = observer.ProductionExactRuntimeCanaryLiveObserver.load_exact_d()
        with self.assertRaises(TypeError):
            pickle.dumps(product)
        with self.assertRaises(TypeError):
            product._transport = object()  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            product._tooling_observer = object()  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            type(
                "ForgedLiveObserver",
                (observer.ProductionExactRuntimeCanaryLiveObserver,),
                {},
            )
        with self.assertRaisesRegex(
            observer.ExactRuntimeCanaryLiveObserverError,
            "provenance",
        ):
            product.observe(  # type: ignore[arg-type]
                object(), object(), object(), object()
            )

    def test_locked_observation_rejects_forgery_subclass_and_pickle(self) -> None:
        with self.assertRaises(TypeError):
            type(
                "ForgedLockedLiveObservation",
                (observer.LockedExactRuntimeCanaryObservation,),
                {},
            )
        forged = object.__new__(observer.LockedExactRuntimeCanaryObservation)
        with self.assertRaises(TypeError):
            pickle.dumps(forged)
        with self.assertRaisesRegex(TypeError, "provenance"):
            observer.LockedExactRuntimeCanaryObservation(
                canary=object(),  # type: ignore[arg-type]
                scm=object(),  # type: ignore[arg-type]
                endpoint=object(),  # type: ignore[arg-type]
                writer=object(),  # type: ignore[arg-type]
                tooling=object(),  # type: ignore[arg-type]
                transport=object(),  # type: ignore[arg-type]
                base=Path("."),
                initial_snapshots={},
                initial_workspace_node=("node", 0),
                source_seals={},
                stable={},
                tooling_stable_sha256="0" * 64,
                result=object(),  # type: ignore[arg-type]
                _construction_token=object(),
            )


@unittest.skipUnless(os.name == "nt", "真实 SQLite/Win32 lease fixture 只在 Windows 执行")
class ExactRuntimeCanaryLiveDatabaseVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RunnerFixture(
            methodName=(
                "test_real_file_canary_runs_under_same_live_lease_and_replays_exact_result"
            )
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        with closing(
            sqlite3.connect(
                self.fixture.state / "research_workspace.sqlite3"
            )
        ) as connection:
            row = connection.execute(
                "SELECT node_id,revision FROM research_workspace_node "
                "ORDER BY node_id LIMIT 1"
            ).fetchone()
        assert row is not None
        self.initial_node = (str(row[0]), int(row[1]))
        self.request = ExactRuntimeCanaryRequest.from_document(
            self.fixture.request
        )

    def verify(self, evidence):
        return observer._verify_database_paths(  # noqa: SLF001
            base=self.fixture.state,
            request=self.request,
            evidence=evidence,
            initial_workspace_node=self.initial_node,
        )

    def run_main_only(self):
        return self.fixture.runner.run(self.fixture.lease, "ab" * 24)

    def forged_product_chain(self):
        canary = object.__new__(LockedExactRuntimeCanaryInput)
        workspace = _WorkspaceCloseProbe()
        object.__setattr__(canary, "_state", "live_result")
        object.__setattr__(canary, "_live_observation", None)
        object.__setattr__(canary, "_controller_tooling_observation", None)
        object.__setattr__(canary, "_workspace", workspace)
        scm = object.__new__(LockedWindowsScmProcessObservation)
        endpoint = object.__new__(LockedWindowsEndpointObservation)
        writer = object.__new__(LockedWindowsWriterLeaseObservation)
        tooling = object.__new__(
            LockedExactRuntimeControllerToolingObservation
        )
        tooling_core = _ToolingCoreProbe()
        object.__setattr__(tooling, "_core", tooling_core)
        object.__setattr__(tooling, "_canary", canary)
        object.__setattr__(tooling, "_sealed", True)
        object.__setattr__(canary, "_controller_tooling_observation", tooling)
        return canary, scm, endpoint, writer, tooling, tooling_core, workspace

    def test_controller_rechecks_two_real_final_databases(self) -> None:
        evidence = self.run_main_only()
        verified = self.verify(evidence)
        self.assertEqual(
            ("comments", "research_workspace"),
            tuple(item.database_name for item in verified),
        )
        self.assertTrue(all(item.final_consistent_bytes > 100 for item in verified))
        self.assertEqual(
            [
                "ExactRuntimeCanaryLiveObservationEvidence",
                "ExactRuntimeCanaryLiveObserverError",
                "LockedExactRuntimeCanaryObservation",
                "ProductionExactRuntimeCanaryLiveObserver",
            ],
            observer.__all__,
        )

    def test_post_result_database_write_is_not_accepted(self) -> None:
        evidence = self.run_main_only()
        path = self.fixture.state / "comments.sqlite3"
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.execute(
                "INSERT INTO actor(actor_id,actor_kind,display_name,created_at) "
                "VALUES('foreign-after-result','other','Foreign','2026-08-28T00:00:00Z')"
            )
        with self.assertRaisesRegex(
            observer.ExactRuntimeCanaryLiveObserverError,
            "consistent/schema/business",
        ):
            self.verify(evidence)

    def test_sidecar_after_result_is_not_accepted(self) -> None:
        evidence = self.run_main_only()
        sidecar = Path(str(self.fixture.state / "comments.sqlite3") + "-journal")
        sidecar.write_bytes(b"third-value")
        with self.assertRaisesRegex(
            observer.ExactRuntimeCanaryLiveObserverError,
            "sidecar",
        ):
            self.verify(evidence)

    def test_product_orchestration_transfers_live_tooling_and_builds_evidence(self) -> None:
        result = self.run_main_only()
        result_document = result.as_dict()
        claim = dict(result_document["writer_lease_claim"])
        stable = {"scm": "1" * 64, "endpoint": "2" * 64, "writer": "3" * 64}
        tooling_stable = "4" * 64
        canary, scm, endpoint, writer, tooling, tooling_core, workspace = (
            self.forged_product_chain()
        )
        databases = tuple(
            observer._DatabaseVerification(  # noqa: SLF001
                database_name=name,
                final_consistent_bytes=100 + index,
                final_consistent_sha256=str(index + 5) * 64,
                final_schema_sha256=str(index + 7) * 64,
                final_business_summary_sha256=str(index + 9) * 64,
            )
            for index, name in enumerate(("comments", "research_workspace"))
        )
        initial = {"comments": {}, "research_workspace": {}}
        source_seals = {"comments": "a" * 64, "research_workspace": "b" * 64}
        product = observer.ProductionExactRuntimeCanaryLiveObserver.load_exact_d()
        with (
            mock.patch.object(
                LockedExactRuntimeCanaryInput,
                "request",
                new_callable=mock.PropertyMock,
                return_value=self.request,
            ),
            mock.patch.object(LockedExactRuntimeCanaryInput, "checkpoint_live"),
            mock.patch.object(
                LockedExactRuntimeCanaryInput, "_begin_result_observation"
            ) as begin,
            mock.patch.object(
                LockedExactRuntimeCanaryInput, "_commit_result_observation"
            ) as commit,
            mock.patch.object(
                ProductionExactRuntimeControllerToolingObserver,
                "observe",
                return_value=tooling,
            ),
            mock.patch.object(
                ProductionExactRuntimeCanaryTransport,
                "post",
                return_value=ExactRuntimeCanaryHttpResponse(
                    status=200, body=result.canonical_bytes()
                ),
            ) as post,
            mock.patch.object(observer.secrets, "token_hex", return_value="ab" * 24),
            mock.patch.object(observer, "_database_base", return_value=self.fixture.state),
            mock.patch.object(
                observer,
                "_capture_initial_database_state",
                return_value=(initial, self.initial_node),
            ),
            mock.patch.object(observer, "_source_seal_hashes", return_value=source_seals),
            mock.patch.object(observer, "_live_chain", return_value=(stable, claim)),
            mock.patch.object(
                observer, "_tooling_stable_sha256", return_value=tooling_stable
            ),
            mock.patch.object(observer, "_verify_database_paths", return_value=databases),
        ):
            live = product.observe(canary, scm, endpoint, writer)
            document = live.build_evidence().as_dict()
        self.assertEqual(tooling_stable, document["controller_tooling_stable_sha256"])
        self.assertEqual(result.evidence_sha256, document["result_evidence_sha256"])
        begin.assert_called_once()
        commit.assert_called_once()
        post.assert_called_once_with("ab" * 24)
        self.assertFalse(tooling_core.closed)
        self.assertIs(canary._live_observation, live)  # noqa: SLF001
        canary.close()
        self.assertTrue(tooling_core.closed)
        self.assertTrue(workspace.released)
        self.assertIsNone(canary._live_observation)  # noqa: SLF001

    def test_transport_failure_closes_tooling_and_aborts_pending_result(self) -> None:
        canary, scm, endpoint, writer, tooling, tooling_core, _workspace = (
            self.forged_product_chain()
        )
        stable = {"scm": "1" * 64, "endpoint": "2" * 64, "writer": "3" * 64}
        claim = dict(self.fixture.lease.record_document)
        initial = {"comments": {}, "research_workspace": {}}
        source_seals = {"comments": "a" * 64, "research_workspace": "b" * 64}
        product = observer.ProductionExactRuntimeCanaryLiveObserver.load_exact_d()
        with (
            mock.patch.object(
                LockedExactRuntimeCanaryInput,
                "request",
                new_callable=mock.PropertyMock,
                return_value=self.request,
            ),
            mock.patch.object(LockedExactRuntimeCanaryInput, "checkpoint_live"),
            mock.patch.object(
                LockedExactRuntimeCanaryInput, "_begin_result_observation"
            ) as begin,
            mock.patch.object(
                LockedExactRuntimeCanaryInput, "_abort_result_observation"
            ) as abort,
            mock.patch.object(
                ProductionExactRuntimeControllerToolingObserver,
                "observe",
                return_value=tooling,
            ),
            mock.patch.object(
                ProductionExactRuntimeCanaryTransport,
                "post",
                side_effect=ExactRuntimeCanaryTransportError("closed fixture failure"),
            ),
            mock.patch.object(observer.secrets, "token_hex", return_value="ab" * 24),
            mock.patch.object(observer, "_database_base", return_value=self.fixture.state),
            mock.patch.object(
                observer,
                "_capture_initial_database_state",
                return_value=(initial, self.initial_node),
            ),
            mock.patch.object(observer, "_source_seal_hashes", return_value=source_seals),
            mock.patch.object(observer, "_live_chain", return_value=(stable, claim)),
            mock.patch.object(
                observer, "_tooling_stable_sha256", return_value="4" * 64
            ),
            self.assertRaisesRegex(
                observer.ExactRuntimeCanaryLiveObserverError,
                "fixed HTTP/result",
            ),
        ):
            product.observe(canary, scm, endpoint, writer)
        begin.assert_called_once()
        abort.assert_called_once()
        self.assertTrue(tooling_core.closed)

    def test_post_commit_database_failure_closes_tooling_without_observation(self) -> None:
        result = self.run_main_only()
        claim = dict(result.as_dict()["writer_lease_claim"])
        stable = {"scm": "1" * 64, "endpoint": "2" * 64, "writer": "3" * 64}
        canary, scm, endpoint, writer, tooling, tooling_core, _workspace = (
            self.forged_product_chain()
        )
        initial = {"comments": {}, "research_workspace": {}}
        source_seals = {"comments": "a" * 64, "research_workspace": "b" * 64}
        product = observer.ProductionExactRuntimeCanaryLiveObserver.load_exact_d()
        with (
            mock.patch.object(
                LockedExactRuntimeCanaryInput,
                "request",
                new_callable=mock.PropertyMock,
                return_value=self.request,
            ),
            mock.patch.object(LockedExactRuntimeCanaryInput, "checkpoint_live"),
            mock.patch.object(
                LockedExactRuntimeCanaryInput, "_begin_result_observation"
            ),
            mock.patch.object(
                LockedExactRuntimeCanaryInput, "_commit_result_observation"
            ) as commit,
            mock.patch.object(
                LockedExactRuntimeCanaryInput, "_abort_result_observation"
            ) as abort,
            mock.patch.object(
                ProductionExactRuntimeControllerToolingObserver,
                "observe",
                return_value=tooling,
            ),
            mock.patch.object(
                ProductionExactRuntimeCanaryTransport,
                "post",
                return_value=ExactRuntimeCanaryHttpResponse(
                    status=200, body=result.canonical_bytes()
                ),
            ),
            mock.patch.object(observer.secrets, "token_hex", return_value="ab" * 24),
            mock.patch.object(observer, "_database_base", return_value=self.fixture.state),
            mock.patch.object(
                observer,
                "_capture_initial_database_state",
                return_value=(initial, self.initial_node),
            ),
            mock.patch.object(observer, "_source_seal_hashes", return_value=source_seals),
            mock.patch.object(observer, "_live_chain", return_value=(stable, claim)),
            mock.patch.object(
                observer, "_tooling_stable_sha256", return_value="4" * 64
            ),
            mock.patch.object(
                observer,
                "_verify_database_paths",
                side_effect=observer.ExactRuntimeCanaryLiveObserverError(
                    "final database drift"
                ),
            ),
            self.assertRaisesRegex(
                observer.ExactRuntimeCanaryLiveObserverError,
                "final database drift",
            ),
        ):
            product.observe(canary, scm, endpoint, writer)
        commit.assert_called_once()
        abort.assert_called_once()
        self.assertTrue(tooling_core.closed)

    def test_tooling_close_unknown_keeps_input_and_workspace_reserved(self) -> None:
        result = self.run_main_only()
        canary, scm, endpoint, writer, tooling, _core, workspace = (
            self.forged_product_chain()
        )
        failing_core = _ToolingCoreProbe(fail_close=True)
        object.__setattr__(tooling, "_core", failing_core)
        live = observer.LockedExactRuntimeCanaryObservation(
            canary=canary,
            scm=scm,
            endpoint=endpoint,
            writer=writer,
            tooling=tooling,
            transport=ProductionExactRuntimeCanaryTransport.load_exact_d(),
            base=self.fixture.state,
            initial_snapshots={"comments": {}, "research_workspace": {}},
            initial_workspace_node=self.initial_node,
            source_seals={"comments": "a" * 64, "research_workspace": "b" * 64},
            stable={"scm": "1" * 64, "endpoint": "2" * 64, "writer": "3" * 64},
            tooling_stable_sha256="4" * 64,
            result=result,
            _construction_token=observer._LIVE_OBSERVATION_TOKEN,  # noqa: SLF001
        )
        with self.assertRaisesRegex(
            observer.ExactRuntimeCanaryLiveObserverError,
            "结果不明",
        ):
            canary.close()
        self.assertEqual("owner_crash_only", live._state)  # noqa: SLF001
        self.assertIs(canary._live_observation, live)  # noqa: SLF001
        self.assertIs(  # noqa: SLF001
            canary._controller_tooling_observation, tooling
        )
        self.assertFalse(workspace.released)


if __name__ == "__main__":
    unittest.main()
