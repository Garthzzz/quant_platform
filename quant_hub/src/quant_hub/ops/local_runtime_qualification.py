"""e.4.3 process-local qualification over the exact live canary chain.

The persistent aggregate produced here is audit evidence only.  The live
qualification keeps the exact e.4.2 observation reachable and rebuilds every
hash from live upstream capabilities before exposing any property.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from .local_exact_release_compatibility import (
    build_exact_release_compatibility_evidence,
)
from .local_exact_runtime_canary_evidence import ExactRuntimeCanaryRequest
from .local_exact_runtime_canary_input import LockedExactRuntimeCanaryInput
from .local_exact_runtime_canary_live_observer import (
    ExactRuntimeCanaryLiveObservationEvidence,
    LockedExactRuntimeCanaryObservation,
)
from .local_exact_runtime_controller_tooling_observer import (
    ExactRuntimeControllerToolingObservationEvidence,
    LockedExactRuntimeControllerToolingObservation,
)
from .local_release_identity import canonical_bytes, identity_sha256
from .local_runtime_qualification_evidence import (
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
    LocalRuntimeQualificationAggregateEvidence,
    build_local_runtime_qualification_evidence,
    parse_local_runtime_qualification_evidence_bytes,
)


_PRODUCER_TOKEN = object()
_QUALIFICATION_TOKEN = object()
_DATABASE_ORDER = ("comments", "research_workspace")
_SOURCE_SEAL_FIELDS = {"database_name", "seal_sha256"}
_FINAL_DATABASE_FIELDS = {
    "database_name",
    "final_consistent_bytes",
    "final_consistent_sha256",
    "final_schema_sha256",
    "final_business_summary_sha256",
}
_TOOLING_STABLE_FIELDS = (
    "tooling_sha256",
    "manifest_sha256",
    "package_inventory_sha256",
    "python_sha256",
    "service_host_sha256",
)


class LocalRuntimeQualificationError(RuntimeError):
    """The exact live chain cannot support a stable formal aggregate."""


def _exact_ordered_rows(
    value: object,
    *,
    fields: set[str],
    label: str,
) -> list[dict[str, object]]:
    if type(value) is not list or len(value) != len(_DATABASE_ORDER):
        raise LocalRuntimeQualificationError(f"{label} 数据库顺序不闭合")
    rows: list[dict[str, object]] = []
    for expected_name, item in zip(_DATABASE_ORDER, value, strict=True):
        if (
            type(item) is not dict
            or set(item) != fields
            or item.get("database_name") != expected_name
        ):
            raise LocalRuntimeQualificationError(f"{label} 数据库成员不闭合")
        rows.append(dict(item))
    return rows


def _tooling_stable_document(
    tooling: LockedExactRuntimeControllerToolingObservation,
) -> tuple[dict[str, object], str]:
    if type(tooling) is not LockedExactRuntimeControllerToolingObservation:
        raise LocalRuntimeQualificationError("controller tooling 不是 exact live capability")
    evidence = tooling.build_evidence()
    if type(evidence) is not ExactRuntimeControllerToolingObservationEvidence:
        raise LocalRuntimeQualificationError("controller tooling 没有返回 exact evidence")
    document = evidence.as_dict()
    stable = {field: document.get(field) for field in _TOOLING_STABLE_FIELDS}
    if any(type(value) is not str for value in stable.values()):
        raise LocalRuntimeQualificationError("controller tooling stable material 不闭合")
    return stable, identity_sha256(stable)


def _live_production_state_order_sha256(
    canary: LockedExactRuntimeCanaryInput,
) -> str:
    from .local_deployment_persistence import (
        _locked_production_state_order_sha256,
    )

    return _locked_production_state_order_sha256(
        canary._sources,  # noqa: SLF001 - exact live source chain.
        persistence=canary._persistence,  # noqa: SLF001
        workspace=canary._workspace,  # noqa: SLF001
    )


def _aggregate_payload(
    observation: LockedExactRuntimeCanaryObservation,
) -> dict[str, object]:
    if type(observation) is not LockedExactRuntimeCanaryObservation:
        raise LocalRuntimeQualificationError("formal qualification 只接受 exact live observation")
    canary = observation._canary  # noqa: SLF001 - exact upstream ownership seam.
    tooling = observation._tooling  # noqa: SLF001 - exact upstream ownership seam.
    if (
        type(canary) is not LockedExactRuntimeCanaryInput
        or type(tooling) is not LockedExactRuntimeControllerToolingObservation
        or canary._live_observation is not observation  # noqa: SLF001
        or canary._controller_tooling_observation is not tooling  # noqa: SLF001
    ):
        raise LocalRuntimeQualificationError("formal qualification upstream owner 漂移")

    canary._closures.checkpoint_unchanged()  # noqa: SLF001
    canary.checkpoint_live()
    production_state_before_order_sha256 = (
        _live_production_state_order_sha256(canary)
    )
    request = canary.request
    if type(request) is not ExactRuntimeCanaryRequest:
        raise LocalRuntimeQualificationError("canary request 不是 exact typed request")
    request_document = request.as_dict()
    compatibility = build_exact_release_compatibility_evidence(
        canary._closures  # noqa: SLF001 - rebuild from live exact closures.
    )
    closure_sha256 = identity_sha256(
        canary._closures.metadata()  # noqa: SLF001 - live closure checkpoint.
    )
    live_before = observation.build_evidence()
    if type(live_before) is not ExactRuntimeCanaryLiveObservationEvidence:
        raise LocalRuntimeQualificationError("live canary 没有返回 exact evidence")
    tooling_document, tooling_stable_sha256 = _tooling_stable_document(tooling)
    canary.checkpoint_live()
    live_after = observation.build_evidence()
    if (
        type(live_after) is not ExactRuntimeCanaryLiveObservationEvidence
        or live_after.canonical_bytes() != live_before.canonical_bytes()
    ):
        raise LocalRuntimeQualificationError("formal aggregate 重建窗口内 live evidence 漂移")

    live_document = live_after.as_dict()
    if live_document.get("controller_tooling_stable_sha256") != tooling_stable_sha256:
        raise LocalRuntimeQualificationError("live canary 与 controller tooling 不是同一稳定链")
    source_seals = _exact_ordered_rows(
        live_document.get("production_state_source_seals"),
        fields=_SOURCE_SEAL_FIELDS,
        label="production state before",
    )
    exact_source_seals = [
        {
            "database_name": database,
            "seal_sha256": canary.source_seal(database).seal_sha256,
        }
        for database in _DATABASE_ORDER
    ]
    if source_seals != exact_source_seals:
        raise LocalRuntimeQualificationError(
            "live canary production source seal 与 exact input 漂移"
        )
    final_databases = _exact_ordered_rows(
        live_document.get("databases"),
        fields=_FINAL_DATABASE_FIELDS,
        label="production state after",
    )
    production_state_after_order_sha256 = (
        _live_production_state_order_sha256(canary)
    )
    if (
        production_state_after_order_sha256
        != production_state_before_order_sha256
    ):
        raise LocalRuntimeQualificationError(
            "formal aggregate 窗口内 production state 漂移"
        )
    required_live_hashes = {
        "scm_stable_sha256",
        "endpoint_stable_sha256",
        "writer_stable_sha256",
        "result_evidence_sha256",
    }
    if any(type(live_document.get(field)) is not str for field in required_live_hashes):
        raise LocalRuntimeQualificationError("live canary aggregate hash 不闭合")

    # replacement monitor 已在完整 rescan 前启动；该末端 checkpoint 将
    # compatibility、canary/tooling 与两次 production-state 观察全部夹在同一
    # release namespace 无 ABA 窗口内。
    canary._closures.checkpoint_unchanged()  # noqa: SLF001

    return {
        "schema_version": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
        "scope": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
        "attempt_id": request_document["attempt_id"],
        "nonce": request_document["nonce"],
        "operation": request_document["operation"],
        "role": request_document["role"],
        "start_nonce": request_document["start_nonce"],
        "state_identity_sha256": request_document["state_identity_sha256"],
        "authorization_sha256": request_document["authorization_sha256"],
        "release_compatibility_sha256": compatibility.aggregate_sha256,
        "release_closure_sha256": closure_sha256,
        "production_state_before_order_sha256": (
            production_state_before_order_sha256
        ),
        "production_state_after_order_sha256": (
            production_state_after_order_sha256
        ),
        "scm_before_after_sha256": live_document["scm_stable_sha256"],
        "endpoint_before_after_sha256": live_document["endpoint_stable_sha256"],
        "writer_before_after_sha256": live_document["writer_stable_sha256"],
        "canary_request_sha256": request.request_sha256,
        "canary_result_sha256": live_document["result_evidence_sha256"],
        "canary_database_order_sha256": identity_sha256(final_databases),
        "runtime_tooling_manifest_sha256": tooling_document["manifest_sha256"],
        "controller_tooling_observation_sha256": tooling_stable_sha256,
    }


def _rebuild_aggregate(
    observation: LockedExactRuntimeCanaryObservation,
) -> LocalRuntimeQualificationAggregateEvidence:
    document = build_local_runtime_qualification_evidence(
        _aggregate_payload(observation)
    )
    return LocalRuntimeQualificationAggregateEvidence.from_document(document)


class LockedLocalRuntimeQualification:
    """Non-serializable live qualification; persistent hashes cannot rebuild it."""

    __slots__ = ("_aggregate_raw", "_observation", "_sealed", "_state")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("local runtime qualification 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("local runtime qualification 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        observation: LockedExactRuntimeCanaryObservation,
        aggregate: LocalRuntimeQualificationAggregateEvidence,
        *,
        token: object,
    ):
        if (
            token is not _QUALIFICATION_TOKEN
            or type(observation) is not LockedExactRuntimeCanaryObservation
            or type(aggregate) is not LocalRuntimeQualificationAggregateEvidence
        ):
            raise TypeError("local runtime qualification provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._observation = observation
        self._aggregate_raw = aggregate.canonical_bytes()
        self._state = "live"
        observation._register_qualification(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("local runtime qualification is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(self) -> LocalRuntimeQualificationAggregateEvidence:
        if self._state != "live":
            raise LocalRuntimeQualificationError("local runtime qualification 已关闭或消费")
        rebuilt = _rebuild_aggregate(self._observation)
        if rebuilt.canonical_bytes() != self._aggregate_raw:
            object.__setattr__(self, "_state", "revoked")
            raise LocalRuntimeQualificationError("local runtime qualification aggregate 漂移")
        return rebuilt

    @property
    def scope(self) -> str:
        self._assert_live()
        return "exact_local_runtime_qualification_process_local"

    @property
    def qualification_sha256(self) -> str:
        return self._assert_live().aggregate_sha256

    def build_evidence(self) -> LocalRuntimeQualificationAggregateEvidence:
        return self._assert_live()

    def _prepare_b2_consume(
        self,
        persistence: object,
        lock: object,
        workspace: object,
    ) -> LocalRuntimeQualificationAggregateEvidence:
        canary = self._observation._canary  # noqa: SLF001
        if (
            getattr(canary, "_persistence", None) is not persistence
            or getattr(canary, "_lock", None) is not lock
            or getattr(canary, "_workspace", None) is not workspace
            or getattr(canary, "_live_observation", None) is not self._observation
        ):
            raise LocalRuntimeQualificationError(
                "qualification 不属于当前 B2 persistence/lock/workspace"
            )
        return self._assert_live()

    def _mark_consumed_from_b2(
        self,
        persistence: object,
        lock: object,
        workspace: object,
        aggregate_sha256: str,
    ) -> None:
        canary = self._observation._canary  # noqa: SLF001
        frozen = parse_local_runtime_qualification_evidence_bytes(
            bytes(self._aggregate_raw)
        )
        if (
            self._state != "live"
            or getattr(canary, "_persistence", None) is not persistence
            or getattr(canary, "_lock", None) is not lock
            or getattr(canary, "_workspace", None) is not workspace
            or frozen.aggregate_sha256 != aggregate_sha256
        ):
            raise LocalRuntimeQualificationError(
                "qualification consume owner/hash 漂移"
            )
        object.__setattr__(self, "_state", "consumed")
        self._observation._release_qualification(self)  # noqa: SLF001

    def close(self) -> None:
        if self._state in {"closed", "consumed"}:
            return
        self._observation._close_qualification_public(self)  # noqa: SLF001

    def _close_from_observation(
        self,
        observation: LockedExactRuntimeCanaryObservation,
    ) -> None:
        if observation is not self._observation:
            raise LocalRuntimeQualificationError(
                "qualification close observation owner 漂移"
            )
        if self._state in {"closed", "consumed"}:
            observation._release_qualification(self)  # noqa: SLF001
            return
        if self._state not in {"live", "revoked"}:
            raise LocalRuntimeQualificationError("qualification close phase 不闭合")
        object.__setattr__(self, "_state", "closed")
        observation._release_qualification(self)  # noqa: SLF001

    def __enter__(self) -> "LockedLocalRuntimeQualification":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class ProductionLocalRuntimeQualificationProducer:
    """No-argument producer accepting only the exact e.4.2 live capability."""

    __slots__ = ("_sealed",)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production runtime qualification producer 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production runtime qualification producer 不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, token: object):
        if token is not _PRODUCER_TOKEN:
            raise TypeError("production runtime qualification producer provenance 无效")
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production runtime qualification producer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionLocalRuntimeQualificationProducer":
        return cls(token=_PRODUCER_TOKEN)

    def qualify(
        self,
        observation: LockedExactRuntimeCanaryObservation,
    ) -> LockedLocalRuntimeQualification:
        if type(observation) is not LockedExactRuntimeCanaryObservation:
            raise LocalRuntimeQualificationError(
                "product qualification 只接受 exact live canary observation"
            )
        aggregate = _rebuild_aggregate(observation)
        qualification: LockedLocalRuntimeQualification | None = None
        try:
            qualification = LockedLocalRuntimeQualification(
                observation,
                aggregate,
                token=_QUALIFICATION_TOKEN,
            )
            qualification._assert_live()  # noqa: SLF001 - rebuild before publish.
            return qualification
        except BaseException:
            if qualification is not None:
                qualification.close()
            raise


__all__: Sequence[str] = (
    "LocalRuntimeQualificationError",
    "LockedLocalRuntimeQualification",
    "ProductionLocalRuntimeQualificationProducer",
)
