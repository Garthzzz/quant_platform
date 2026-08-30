"""Exact production steady service-host bootstrap across START_PENDING/RUNNING."""

from __future__ import annotations

from pathlib import Path
import threading

from quant_hub.config import ensure_no_reparse_components

from .local_deployment_persistence import (
    CrashReleasedFileLock,
    LocalDeploymentPersistence,
    LockedSteadyBootWorkspace,
    PRODUCTION_VM_ROOT_TEXT,
)
from .local_exact_runtime_controller_tooling_observer import (
    ProductionExactRuntimeControllerToolingObserver,
)
from .local_steady_admission_authorization import (
    ProductionSteadyAdmissionAuthorityFactory,
)
from .local_steady_legacy_c_fence import (
    ProductionSteadyLegacyCPrelaunchObserver,
)
from .local_steady_receipt_lineage import (
    ProductionSteadyReceiptLineageObserver,
)
from .local_steady_start_authorization import (
    ProductionExactSteadyStartAuthorizer,
)
from .local_windows_endpoint_observer import ProductionWindowsEndpointObserver
from .local_windows_job_child_launcher import (
    LockedServiceChildLaunchLifecycle,
    LockedServiceChildLifetime,
    ProductionWindowsJobChildLauncher,
    WindowsJobChildOwnerCrashRequired,
)
from .local_windows_scm_process_observer import (
    ProductionWindowsScmProcessObserver,
)
from .local_windows_writer_lease_observer import (
    ProductionWindowsWriterLeaseObserver,
)
from .vm_boundary import validate_production_vm_write_path


_BOOTSTRAP_TOKEN = object()
_SESSION_TOKEN = object()


class SteadyServiceBootstrapError(RuntimeError):
    """The service-host steady boot state machine failed closed."""


class LockedProductionSteadyServiceBootSession:
    """Owns B2 lock/workspace and provisional child until admission completes."""

    __slots__ = (
        "_persistence",
        "_lock",
        "_workspace",
        "_authorization",
        "_scm_input",
        "_lifecycle",
        "_owner_thread",
        "_stop_requested",
        "_state",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production steady boot session 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production steady boot session 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedSteadyBootWorkspace,
        authorization: object,
        scm_input: object,
        lifecycle: LockedServiceChildLaunchLifecycle,
        token: object,
    ) -> None:
        if (
            token is not _SESSION_TOKEN
            or type(persistence) is not LocalDeploymentPersistence
            or persistence._test_only  # noqa: SLF001
            or type(lock) is not CrashReleasedFileLock
            or type(workspace) is not LockedSteadyBootWorkspace
            or type(lifecycle) is not LockedServiceChildLaunchLifecycle
            or lifecycle._workspace is not workspace  # noqa: SLF001
            or lifecycle._authorization is not authorization  # noqa: SLF001
        ):
            raise TypeError("production steady boot session provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._persistence = persistence
        self._lock = lock
        self._workspace = workspace
        self._authorization = authorization
        self._scm_input = scm_input
        self._lifecycle = lifecycle
        self._owner_thread = threading.get_ident()
        self._stop_requested = threading.Event()
        self._state = "child_resumed_start_pending"
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production steady boot session is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_owner(self, *states: str) -> None:
        if threading.get_ident() != self._owner_thread or self._state not in states:
            raise SteadyServiceBootstrapError(
                "steady service boot session state/owner 漂移"
            )

    def request_stop(self) -> None:
        """Cross-thread SCM control signal; it never touches kernel owners."""

        self._stop_requested.set()

    def _assert_continue(self) -> None:
        if self._stop_requested.is_set():
            raise SteadyServiceBootstrapError(
                "steady service stop requested during admission chain"
            )

    def abort(self) -> None:
        if self._state in {"aborted", "admitted_released"}:
            return
        self._assert_owner("child_resumed_start_pending", "running_chain")
        # Never release B2 after an unproven Job/handle close.  In that state
        # only service-host process exit may close the lock and last Job handle.
        if self._workspace._state != "closed":  # noqa: SLF001
            self._workspace.close()
        if self._workspace._state != "closed":  # noqa: SLF001
            raise SteadyServiceBootstrapError(
                "steady abort workspace cleanup did not close"
            )
        if self._lock.held:
            self._lock.release()
        object.__setattr__(self, "_state", "aborted")

    def complete_after_running(self) -> LockedServiceChildLifetime:
        """Run SCM→endpoint→writer→promotion→PREPARE/COMMIT while B2 stays held."""

        self._assert_owner("child_resumed_start_pending")
        self._assert_continue()
        object.__setattr__(self, "_state", "running_chain")
        lifetime: LockedServiceChildLifetime | None = None
        try:
            scm = ProductionWindowsScmProcessObserver.load_exact_d().observe_steady(
                self._persistence,
                self._lock,
                self._workspace,
                self._scm_input,  # type: ignore[arg-type]
            )
            self._assert_continue()
            endpoint = ProductionWindowsEndpointObserver.load_exact_d().observe_steady(
                scm
            )
            self._assert_continue()
            writer = ProductionWindowsWriterLeaseObserver.load_exact_d().observe_steady(
                scm, endpoint
            )
            self._assert_continue()
            admissions = ProductionSteadyAdmissionAuthorityFactory.load_exact_d()
            prepare = admissions.promote_job_to_service_lifetime(
                self._lifecycle,
                self._authorization,  # type: ignore[arg-type]
                scm,
                endpoint,
                writer,
            )
            lifetime = prepare.service_lifetime
            self._assert_continue()
            lifetime.prepare_admission_after_promotion(prepare)
            self._assert_continue()
            commit = admissions.authorize_commit_after_ready_ack(prepare)
            self._assert_continue()
            lifetime.commit_admission_after_ready_ack(commit)
            self._assert_continue()
            lifetime = admissions.confirm_admitted_after_commit(commit)
            self._assert_continue()
            self._workspace.close()
            if self._workspace._state != "closed":  # noqa: SLF001
                raise SteadyServiceBootstrapError(
                    "steady admitted workspace cleanup did not close"
                )
            self._lock.release()
            object.__setattr__(self, "_state", "admitted_released")
            return lifetime
        except BaseException as error:
            if isinstance(error, WindowsJobChildOwnerCrashRequired):
                raise
            cleanup_error: BaseException | None = None
            if lifetime is not None and lifetime._state in {  # noqa: SLF001
                "promotion_pending_admission",
                "prepare_sent",
                "commit_sent_waiting_observation",
                "admitted",
            }:
                try:
                    lifetime.terminate()
                except BaseException as observed:
                    if isinstance(observed, WindowsJobChildOwnerCrashRequired):
                        raise observed from error
                    cleanup_error = observed
            try:
                self.abort()
            except BaseException as observed:
                cleanup_error = cleanup_error or observed
            if cleanup_error is not None:
                if isinstance(
                    cleanup_error, WindowsJobChildOwnerCrashRequired
                ):
                    raise cleanup_error
                raise SteadyServiceBootstrapError(
                    "steady RUNNING chain 失败且 whole-Job cleanup 不可闭合"
                ) from cleanup_error
            raise error


class ProductionSteadyServiceBootstrap:
    """Zero-argument builder for the exact D ordinary steady service start."""

    __slots__ = ("_sealed",)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production steady service bootstrap 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production steady service bootstrap 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, token: object) -> None:
        if token is not _BOOTSTRAP_TOKEN:
            raise TypeError("production steady service bootstrap provenance 无效")
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "ProductionSteadyServiceBootstrap":
        return cls(token=_BOOTSTRAP_TOKEN)

    def begin_prelaunch(self) -> LockedProductionSteadyServiceBootSession:
        root = Path(PRODUCTION_VM_ROOT_TEXT)
        for directory in (
            root / "logs",
            root / "tmp" / "service",
            root / "tmp" / "service" / "pycache",
        ):
            validate_production_vm_write_path(str(directory), allow_root=False)
            directory.mkdir(parents=True, exist_ok=True)
            ensure_no_reparse_components(directory)
        persistence = LocalDeploymentPersistence.production()
        lock = persistence.global_lock()
        lock.acquire()
        workspace: LockedSteadyBootWorkspace | None = None
        try:
            workspace = persistence.bind_steady_boot_workspace(lock)
            facts = persistence.lock_steady_pair_static_facts(lock, workspace)
            closures = persistence.lock_steady_release_closures(
                lock, workspace, facts
            )
            tooling = (
                ProductionExactRuntimeControllerToolingObserver.load_exact_d()
                .observe_steady(workspace, facts, closures)
            )
            lineage = ProductionSteadyReceiptLineageObserver.load_exact_d().observe(
                workspace, facts, closures, tooling
            )
            legacy = ProductionSteadyLegacyCPrelaunchObserver.load_exact_d().observe(
                workspace, facts, closures, tooling, lineage
            )
            authorizer = ProductionExactSteadyStartAuthorizer.load_exact_d()
            authorization = authorizer.authorize(
                workspace, facts, closures, tooling, lineage, legacy
            )
            scm_input = authorizer.bind_scm_process_observation_input(
                workspace, authorization, closures
            )
            lifecycle = ProductionWindowsJobChildLauncher.load_exact_d().launch_steady(
                authorization
            )
            return LockedProductionSteadyServiceBootSession(
                persistence=persistence,
                lock=lock,
                workspace=workspace,
                authorization=authorization,
                scm_input=scm_input,
                lifecycle=lifecycle,
                token=_SESSION_TOKEN,
            )
        except BaseException as error:
            if workspace is not None and workspace._state != "closed":  # noqa: SLF001
                try:
                    workspace.close()
                except BaseException as cleanup_error:
                    raise cleanup_error from error
                if workspace._state != "closed":  # noqa: SLF001
                    raise SteadyServiceBootstrapError(
                        "steady prelaunch workspace cleanup did not close"
                    ) from error
            if lock.held:
                lock.release()
            raise error


__all__ = [
    "LockedProductionSteadyServiceBootSession",
    "ProductionSteadyServiceBootstrap",
    "SteadyServiceBootstrapError",
]
