"""Steady Job promotion 与 PREPARE/ready-ack/COMMIT 的一次性 live authority。

Persistent evidence remains observation-only.  Only this process-local join of
the same B2 workspace, service Job owner, SCM/endpoint/writer capabilities and
fresh post-promotion observations can advance the anonymous admission pipe.
"""

from __future__ import annotations

import threading
from typing import Mapping

from .local_release_identity import identity_sha256
from .local_steady_start_authorization import LockedExactSteadyStartAuthorization
from .local_steady_windows_endpoint_evidence import (
    SteadyWindowsEndpointObservationEvidence,
)
from .local_steady_windows_scm_process_evidence import (
    SteadyWindowsScmProcessObservationEvidence,
)
from .local_steady_windows_writer_lease_evidence import (
    SteadyWindowsWriterLeaseObservationEvidence,
)
from .local_windows_endpoint_observer import LockedSteadyWindowsEndpointObservation
from .local_windows_job_child_launcher import (
    LockedServiceChildLaunchLifecycle,
    LockedServiceChildLifetime,
    WindowsJobChildLauncherError,
    _ADMISSION_CONFIRM_TOKEN,
    _LIFETIME_TOKEN,
    _PROMOTION_TOKEN,
)
from .local_windows_scm_process_observer import (
    LockedSteadyWindowsScmProcessObservation,
)
from .local_windows_writer_lease_observer import (
    LockedSteadyWindowsWriterLeaseObservation,
)


_PREPARE_TOKEN = object()
_COMMIT_TOKEN = object()
_FACTORY_TOKEN = object()
_SHA256_CHARS = frozenset("0123456789abcdef")


class SteadyAdmissionAuthorizationError(RuntimeError):
    """The live steady chain cannot authorize the next admission transition."""


def _hash(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _SHA256_CHARS for character in value)
    ):
        raise SteadyAdmissionAuthorizationError(f"{label} 不是 exact SHA-256")
    return value


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise SteadyAdmissionAuthorizationError(f"{label} 结构漂移")
    return value


def _assert_exact_refs(
    lifecycle: LockedServiceChildLaunchLifecycle,
    authorization: LockedExactSteadyStartAuthorization,
    scm: LockedSteadyWindowsScmProcessObservation,
    endpoint: LockedSteadyWindowsEndpointObservation,
    writer: LockedSteadyWindowsWriterLeaseObservation,
) -> None:
    if (
        type(lifecycle) is not LockedServiceChildLaunchLifecycle
        or type(authorization) is not LockedExactSteadyStartAuthorization
        or type(scm) is not LockedSteadyWindowsScmProcessObservation
        or type(endpoint) is not LockedSteadyWindowsEndpointObservation
        or type(writer) is not LockedSteadyWindowsWriterLeaseObservation
        or lifecycle._authorization is not authorization  # noqa: SLF001
        or scm._inputs._authorization is not authorization  # noqa: SLF001
        or endpoint._scm_observation is not scm  # noqa: SLF001
        or writer._scm is not scm  # noqa: SLF001
        or writer._endpoint is not endpoint  # noqa: SLF001
        or writer._tracking._scm_tracking is not scm._tracking  # noqa: SLF001
        or scm._tracking._workspace is not lifecycle._workspace  # noqa: SLF001
    ):
        raise SteadyAdmissionAuthorizationError(
            "steady promotion chain 不是同一 exact workspace/authorization"
        )
    authorization._assert_live()  # noqa: SLF001
    scm._assert_live()  # noqa: SLF001
    writer._tracking._assert_context()  # noqa: SLF001
    if endpoint._closed:  # noqa: SLF001
        raise SteadyAdmissionAuthorizationError("steady endpoint owner 已关闭")


def _endpoint_response(
    endpoint: SteadyWindowsEndpointObservationEvidence,
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    document = endpoint.as_dict()
    probe = _mapping(document.get("probe"), label="steady endpoint probe")
    response = _mapping(
        probe.get("response"), label="steady endpoint response"
    )
    return document, response


def _assert_evidence_chain(
    *,
    lifecycle: LockedServiceChildLaunchLifecycle,
    authorization: LockedExactSteadyStartAuthorization,
    scm: SteadyWindowsScmProcessObservationEvidence,
    endpoint: SteadyWindowsEndpointObservationEvidence,
    writer: SteadyWindowsWriterLeaseObservationEvidence,
    required_admission_state: str,
    writer_uses_endpoint: bool,
) -> str:
    scm_document = scm.as_dict()
    endpoint_document, response = _endpoint_response(endpoint)
    writer_document = writer.as_dict()
    lease_record = _mapping(
        writer_document.get("lease_record"), label="steady lease_record"
    )
    host = _mapping(scm_document.get("host"), label="steady SCM host")
    child = _mapping(scm_document.get("child"), label="steady SCM child")
    if (
        scm_document.get("authorization_sha256")
        != authorization.authorization_sha256
        or scm_document.get("boot_nonce") != authorization.boot_nonce
        or child.get("pid") != lifecycle._process_id  # noqa: SLF001
        or child.get("creation_time_100ns")
        != lifecycle._child_creation_time_100ns  # noqa: SLF001
        or host.get("creation_time_100ns")
        != lifecycle._host_creation_time_100ns  # noqa: SLF001
        or endpoint_document.get("scm_process_evidence_sha256")
        != scm.evidence_sha256
        or writer_document.get("scm_process_evidence_sha256")
        != scm.evidence_sha256
    ):
        raise SteadyAdmissionAuthorizationError(
            "steady SCM/endpoint/writer 与 launched host/child identity 漂移"
        )
    if writer_uses_endpoint and (
        writer_document.get("endpoint_evidence_sha256")
        != endpoint.evidence_sha256
    ):
        raise SteadyAdmissionAuthorizationError(
            "ready-ack writer 未绑定唯一 endpoint challenge"
        )
    expected_job = lifecycle._job_identity_sha256  # noqa: SLF001
    expected_admission = lifecycle._admission_binding_sha256  # noqa: SLF001
    prelaunch_fence = _hash(
        lifecycle._prelaunch_fence_sha256,  # noqa: SLF001
        label="steady prelaunch fence",
    )
    if (
        response.get("job_identity_sha256") != expected_job
        or response.get("admission_binding_sha256") != expected_admission
        or response.get("admission_state") != required_admission_state
        or response.get("authority") != "claim_not_independently_observed"
        or lease_record.get("job_identity_sha256") != expected_job
        or lease_record.get("admission_binding_sha256") != expected_admission
    ):
        raise SteadyAdmissionAuthorizationError(
            "steady Job/admission claim 未被 host lifecycle + writer 共同闭合"
        )
    return identity_sha256(
        {
            "schema_version": "qrh-steady-live-chain-aggregate/v1",
            "required_admission_state": required_admission_state,
            "authorization_sha256": authorization.authorization_sha256,
            "job_identity_sha256": expected_job,
            "admission_binding_sha256": expected_admission,
            "prelaunch_fence_sha256": prelaunch_fence,
            "scm_evidence_sha256": scm.evidence_sha256,
            "endpoint_evidence_sha256": endpoint.evidence_sha256,
            "writer_evidence_sha256": writer.evidence_sha256,
        }
    )


class LockedSteadyAdmissionPrepareAuthorization:
    """Registered destination of Job promotion; usable for one PREPARE only."""

    __slots__ = (
        "_workspace",
        "_lifetime",
        "_authorization",
        "_scm",
        "_endpoint",
        "_writer",
        "_chain_aggregate_sha256",
        "_owner_thread",
        "_state",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady admission prepare authorization 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady admission prepare authorization 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        lifetime: LockedServiceChildLifetime,
        authorization: LockedExactSteadyStartAuthorization,
        scm: LockedSteadyWindowsScmProcessObservation,
        endpoint: LockedSteadyWindowsEndpointObservation,
        writer: LockedSteadyWindowsWriterLeaseObservation,
        chain_aggregate_sha256: str,
        token: object,
    ) -> None:
        if (
            token is not _PREPARE_TOKEN
            or type(lifetime) is not LockedServiceChildLifetime
            or type(authorization) is not LockedExactSteadyStartAuthorization
            or type(scm) is not LockedSteadyWindowsScmProcessObservation
            or type(endpoint) is not LockedSteadyWindowsEndpointObservation
            or type(writer) is not LockedSteadyWindowsWriterLeaseObservation
        ):
            raise TypeError("steady admission prepare provenance 无效")
        _hash(chain_aggregate_sha256, label="steady live-chain aggregate")
        workspace = authorization._workspace  # noqa: SLF001
        object.__setattr__(self, "_sealed", False)
        self._workspace = workspace
        self._lifetime = lifetime
        self._authorization = authorization
        self._scm = scm
        self._endpoint = endpoint
        self._writer = writer
        self._chain_aggregate_sha256 = chain_aggregate_sha256
        self._owner_thread = threading.get_ident()
        self._state = "live"
        workspace._register_steady_admission_authorization(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("steady admission prepare authorization is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def service_lifetime(self) -> LockedServiceChildLifetime:
        self._assert_for_prepare(self._lifetime)
        return self._lifetime

    def _assert_for_prepare(self, lifetime: LockedServiceChildLifetime) -> None:
        if (
            threading.get_ident() != self._owner_thread
            or self._state != "live"
            or lifetime is not self._lifetime
            or self
            not in self._workspace._steady_admission_authorizations  # noqa: SLF001
            or lifetime._state != "promotion_pending_admission"  # noqa: SLF001
            or lifetime._chain_aggregate_sha256  # noqa: SLF001
            != self._chain_aggregate_sha256
        ):
            raise SteadyAdmissionAuthorizationError(
                "steady PREPARE authorization 已消费或 provenance 漂移"
            )
        self._workspace._assert_live()  # noqa: SLF001
        self._authorization._assert_live()  # noqa: SLF001
        self._scm._assert_live()  # noqa: SLF001
        self._writer._tracking._assert_context()  # noqa: SLF001

    def _mark_prepared(self, lifetime: LockedServiceChildLifetime) -> None:
        self._assert_for_prepare(lifetime)
        object.__setattr__(self, "_state", "prepared")

    def _close_from_workspace(self, workspace: object) -> None:
        if workspace is not self._workspace:
            raise SteadyAdmissionAuthorizationError(
                "steady PREPARE workspace close owner 漂移"
            )
        self._lifetime.terminate()
        object.__setattr__(self, "_state", "closed")
        self._workspace._release_steady_admission_authorization(self)  # noqa: SLF001


class LockedSteadyAdmissionCommitAuthorization:
    """Destination-first replacement after the unique ready acknowledgement."""

    __slots__ = (
        "_workspace",
        "_lifetime",
        "_authorization",
        "_scm",
        "_endpoint",
        "_writer",
        "_ready_ack_binding_sha256",
        "_ready_chain_aggregate_sha256",
        "_owner_thread",
        "_state",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady admission commit authorization 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady admission commit authorization 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        source: LockedSteadyAdmissionPrepareAuthorization,
        ready_ack_binding_sha256: str,
        ready_chain_aggregate_sha256: str,
        token: object,
    ) -> None:
        if (
            token is not _COMMIT_TOKEN
            or type(source) is not LockedSteadyAdmissionPrepareAuthorization
            or source._state != "prepared"  # noqa: SLF001
        ):
            raise TypeError("steady admission commit provenance 无效")
        _hash(ready_ack_binding_sha256, label="steady ready-ack binding")
        _hash(ready_chain_aggregate_sha256, label="steady ready chain")
        object.__setattr__(self, "_sealed", False)
        self._workspace = source._workspace  # noqa: SLF001
        self._lifetime = source._lifetime  # noqa: SLF001
        self._authorization = source._authorization  # noqa: SLF001
        self._scm = source._scm  # noqa: SLF001
        self._endpoint = source._endpoint  # noqa: SLF001
        self._writer = source._writer  # noqa: SLF001
        self._ready_ack_binding_sha256 = ready_ack_binding_sha256
        self._ready_chain_aggregate_sha256 = ready_chain_aggregate_sha256
        self._owner_thread = threading.get_ident()
        self._state = "live"
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("steady admission commit authorization is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_for_commit(self, lifetime: LockedServiceChildLifetime) -> str:
        if (
            threading.get_ident() != self._owner_thread
            or self._state != "live"
            or lifetime is not self._lifetime
            or self
            not in self._workspace._steady_admission_authorizations  # noqa: SLF001
            or lifetime._state != "prepare_sent"  # noqa: SLF001
        ):
            raise SteadyAdmissionAuthorizationError(
                "steady COMMIT authorization 已消费或 provenance 漂移"
            )
        self._workspace._assert_live()  # noqa: SLF001
        self._authorization._assert_live()  # noqa: SLF001
        self._scm._assert_live()  # noqa: SLF001
        self._writer._tracking._assert_context()  # noqa: SLF001
        return self._ready_ack_binding_sha256

    def _mark_commit_sent(self, lifetime: LockedServiceChildLifetime) -> None:
        self._assert_for_commit(lifetime)
        object.__setattr__(self, "_state", "commit_sent")

    def _close_from_workspace(self, workspace: object) -> None:
        if workspace is not self._workspace:
            raise SteadyAdmissionAuthorizationError(
                "steady COMMIT workspace close owner 漂移"
            )
        self._lifetime.terminate()
        object.__setattr__(self, "_state", "closed")
        self._workspace._release_steady_admission_authorization(self)  # noqa: SLF001


class ProductionSteadyAdmissionAuthorityFactory:
    """Zero-argument product factory; all authority inputs remain exact/live."""

    __slots__ = ("_sealed",)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production steady admission factory 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production steady admission factory 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, token: object) -> None:
        if token is not _FACTORY_TOKEN:
            raise TypeError("production steady admission factory provenance 无效")
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "ProductionSteadyAdmissionAuthorityFactory":
        return cls(token=_FACTORY_TOKEN)

    def promote_job_to_service_lifetime(
        self,
        lifecycle: LockedServiceChildLaunchLifecycle,
        authorization: LockedExactSteadyStartAuthorization,
        scm: LockedSteadyWindowsScmProcessObservation,
        endpoint: LockedSteadyWindowsEndpointObservation,
        writer: LockedSteadyWindowsWriterLeaseObservation,
    ) -> LockedSteadyAdmissionPrepareAuthorization:
        _assert_exact_refs(lifecycle, authorization, scm, endpoint, writer)
        lifecycle._assert_owner("live")  # noqa: SLF001
        scm_before = scm.build_evidence()
        endpoint_evidence = endpoint.build_evidence()
        writer_evidence = writer.build_evidence()
        scm_after = scm.build_evidence()
        if scm_after.evidence_sha256 != scm_before.evidence_sha256:
            raise SteadyAdmissionAuthorizationError(
                "steady promotion SCM before/after 漂移"
            )
        chain = _assert_evidence_chain(
            lifecycle=lifecycle,
            authorization=authorization,
            scm=scm_before,
            endpoint=endpoint_evidence,
            writer=writer_evidence,
            required_admission_state="closed_pending_promotion",
            writer_uses_endpoint=False,
        )
        lifetime = LockedServiceChildLifetime(
            lifecycle,
            chain_aggregate_sha256=chain,
            token=_LIFETIME_TOKEN,
        )
        prepare = LockedSteadyAdmissionPrepareAuthorization(
            lifetime=lifetime,
            authorization=authorization,
            scm=scm,
            endpoint=endpoint,
            writer=writer,
            chain_aggregate_sha256=chain,
            token=_PREPARE_TOKEN,
        )
        try:
            lifecycle._commit_registered_promotion(  # noqa: SLF001
                lifetime,
                prepare,
                token=_PROMOTION_TOKEN,
            )
        except BaseException:
            prepare._close_from_workspace(prepare._workspace)  # noqa: SLF001
            raise
        return prepare

    def authorize_commit_after_ready_ack(
        self,
        prepare: LockedSteadyAdmissionPrepareAuthorization,
    ) -> LockedSteadyAdmissionCommitAuthorization:
        if type(prepare) is not LockedSteadyAdmissionPrepareAuthorization:
            raise TypeError("ready-ack requires exact prepare authorization")
        lifetime = prepare._lifetime  # noqa: SLF001
        if prepare._state != "prepared":  # noqa: SLF001
            raise SteadyAdmissionAuthorizationError(
                "PREPARE 尚未发送或已被消费"
            )
        prepare._workspace._assert_live()  # noqa: SLF001
        endpoint_evidence = prepare._endpoint.build_evidence()  # noqa: SLF001
        endpoint_document, response = _endpoint_response(endpoint_evidence)
        if response.get("admission_state") != "ack_pending":
            raise SteadyAdmissionAuthorizationError(
                "唯一 readiness challenge 未观察到 ack_pending"
            )
        writer_evidence = (
            prepare._writer.build_evidence_after_ready_ack(  # noqa: SLF001
                endpoint_evidence
            )
        )
        scm_evidence = prepare._scm.build_evidence()  # noqa: SLF001
        ready_chain = _assert_evidence_chain(
            lifecycle=lifetime._lifecycle,  # noqa: SLF001
            authorization=prepare._authorization,  # noqa: SLF001
            scm=scm_evidence,
            endpoint=endpoint_evidence,
            writer=writer_evidence,
            required_admission_state="ack_pending",
            writer_uses_endpoint=True,
        )
        probe = _mapping(
            endpoint_document.get("probe"), label="ready endpoint probe"
        )
        challenge = probe.get("challenge")
        if (
            type(challenge) is not str
            or len(challenge) != 48
            or any(character not in _SHA256_CHARS for character in challenge)
        ):
            raise SteadyAdmissionAuthorizationError(
                "readiness challenge 不是 fresh 192-bit lowercase hex"
            )
        ready_ack = identity_sha256(
            {
                "schema_version": "qrh-steady-ready-ack-binding/v1",
                "admission_binding_sha256": lifetime.admission_binding_sha256,
                "job_identity_sha256": lifetime.job_identity_sha256,
                "challenge": challenge,
                "state": "ack_pending",
            }
        )
        commit = LockedSteadyAdmissionCommitAuthorization(
            source=prepare,
            ready_ack_binding_sha256=ready_ack,
            ready_chain_aggregate_sha256=ready_chain,
            token=_COMMIT_TOKEN,
        )
        prepare._workspace._replace_steady_admission_authorization(  # noqa: SLF001
            prepare, commit
        )
        return commit

    def confirm_admitted_after_commit(
        self,
        commit: LockedSteadyAdmissionCommitAuthorization,
    ) -> LockedServiceChildLifetime:
        if type(commit) is not LockedSteadyAdmissionCommitAuthorization:
            raise TypeError("post-commit requires exact commit authorization")
        if commit._state != "commit_sent":  # noqa: SLF001
            raise SteadyAdmissionAuthorizationError(
                "COMMIT 尚未发送或 authorization 已消费"
            )
        commit._workspace._assert_live()  # noqa: SLF001
        endpoint_evidence = commit._endpoint.build_evidence()  # noqa: SLF001
        writer_evidence = commit._writer.build_evidence()  # noqa: SLF001
        scm_evidence = commit._scm.build_evidence()  # noqa: SLF001
        _assert_evidence_chain(
            lifecycle=commit._lifetime._lifecycle,  # noqa: SLF001
            authorization=commit._authorization,  # noqa: SLF001
            scm=scm_evidence,
            endpoint=endpoint_evidence,
            writer=writer_evidence,
            required_admission_state="admitted",
            writer_uses_endpoint=False,
        )
        commit._lifetime._mark_admitted_after_observation(  # noqa: SLF001
            token=_ADMISSION_CONFIRM_TOKEN
        )
        object.__setattr__(commit, "_state", "consumed")
        commit._workspace._release_steady_admission_authorization(  # noqa: SLF001
            commit
        )
        return commit._lifetime  # noqa: SLF001


__all__ = [
    "LockedSteadyAdmissionCommitAuthorization",
    "LockedSteadyAdmissionPrepareAuthorization",
    "ProductionSteadyAdmissionAuthorityFactory",
    "SteadyAdmissionAuthorizationError",
]
