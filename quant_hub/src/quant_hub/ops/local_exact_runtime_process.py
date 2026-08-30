"""Exact service-child orchestration after the writer lease is live."""

from __future__ import annotations

from .local_exact_runtime_import_closure import (
    ProductionExactRuntimeImportClosure,
)
from .local_exact_runtime_admission import LockedExactRuntimeAdmissionGate
from .local_windows_writer_lease_holder import (
    LockedSteadyWindowsWriterLease,
    LockedWindowsWriterLease,
)


class ExactRuntimeProcessError(RuntimeError):
    """The lease-bound exact runtime could not reach or leave its serve loop."""


def run_exact_runtime(lease: LockedWindowsWriterLease) -> int:
    if type(lease) is not LockedWindowsWriterLease:
        raise TypeError("exact runtime process requires the exact live writer lease")
    try:
        closure = ProductionExactRuntimeImportClosure.load_exact_d(lease)
    except BaseException:
        lease._retire_to_owner_crash_only()
        raise
    try:
        closure.activate()
        closure.assert_application_sources()
        from .local_exact_runtime_server import serve_exact_runtime

        result = serve_exact_runtime(lease, closure)
        if type(result) is not int or result != 0:
            raise ExactRuntimeProcessError(
                "exact runtime server returned a non-success status"
            )
        return result
    finally:
        try:
            closure.close()
        except BaseException:
            lease._retire_to_owner_crash_only()
            raise


def run_steady_exact_runtime(
    lease: LockedSteadyWindowsWriterLease,
    gate: LockedExactRuntimeAdmissionGate,
) -> int:
    if (
        type(lease) is not LockedSteadyWindowsWriterLease
        or type(gate) is not LockedExactRuntimeAdmissionGate
    ):
        raise TypeError(
            "steady exact runtime process requires exact live lease and gate"
        )
    try:
        closure = ProductionExactRuntimeImportClosure.load_steady_exact_d(lease)
    except BaseException:
        lease._retire_to_owner_crash_only()
        raise
    try:
        closure.activate()
        closure.assert_application_sources()
        from .local_exact_runtime_server import serve_steady_exact_runtime

        result = serve_steady_exact_runtime(lease, gate, closure)
        if type(result) is not int or result != 0:
            raise ExactRuntimeProcessError(
                "steady exact runtime server returned a non-success status"
            )
        return result
    finally:
        try:
            closure.close()
        except BaseException:
            lease._retire_to_owner_crash_only()
            raise


__all__ = [
    "ExactRuntimeProcessError",
    "run_exact_runtime",
    "run_steady_exact_runtime",
]
