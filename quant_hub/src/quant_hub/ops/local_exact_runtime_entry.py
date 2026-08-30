"""Exact Windows service child entry.

Module import is deliberately standard-library-only.  The product ``main``
parses one fixed argv shape, acquires the exact D-root writer lease, and only
then imports runtime/bootstrap/application code.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys


_ARGUMENT_FLAGS = (
    "--deployment-attempt",
    "--deployment-nonce",
    "--deployment-operation",
    "--deployment-role",
    "--start-nonce",
    "--release-id",
    "--manifest-sha256",
    "--state-identity-sha256",
)

_ARGUMENT_FIELDS = (
    "attempt_id",
    "nonce",
    "operation",
    "role",
    "start_nonce",
    "release_id",
    "manifest_sha256",
    "state_identity_sha256",
)


class ExactRuntimeEntryError(RuntimeError):
    """The service child failed its pre-lease bootstrap contract."""


def _parse_exact_argv(values: object) -> dict[str, str]:
    if type(values) is not tuple or len(values) != 2 * len(_ARGUMENT_FLAGS):
        raise ExactRuntimeEntryError("exact runtime argv length is not closed")
    parsed: dict[str, str] = {}
    for index, (flag, field) in enumerate(
        zip(_ARGUMENT_FLAGS, _ARGUMENT_FIELDS, strict=True)
    ):
        observed_flag = values[index * 2]
        observed_value = values[index * 2 + 1]
        if observed_flag != flag or type(observed_value) is not str or not observed_value:
            raise ExactRuntimeEntryError(
                f"exact runtime argv differs at {flag}"
            )
        parsed[field] = observed_value
    return parsed


def main() -> int:
    raw_arguments = tuple(sys.argv[1:])
    steady = bool(raw_arguments) and raw_arguments[0] == "--authority-kind"
    if steady:
        from .local_steady_runtime_identity import (
            ExactSteadyRuntimeIdentity,
            _parse_exact_steady_argv,
        )

        values = _parse_exact_steady_argv(raw_arguments)
        steady_identity = ExactSteadyRuntimeIdentity(**values)
        pycache_nonce = steady_identity.boot_nonce
        sentinel_identity = {"boot_nonce": pycache_nonce}
    else:
        values = _parse_exact_argv(raw_arguments)
        pycache_nonce = values["start_nonce"]
        sentinel_identity = {"start_nonce": pycache_nonce}
    expected_pycache = (
        "D:\\quant\\quant_platform\\tmp\\service\\pycache\\"
        + pycache_nonce
    )
    if (
        not sys.dont_write_bytecode
        or sys.flags.isolated != 1
        or sys.flags.utf8_mode != 1
        or sys.pycache_prefix != expected_pycache
    ):
        raise ExactRuntimeEntryError(
            "exact runtime interpreter flags/pycache prefix are not closed"
        )
    pycache_sentinel = Path(expected_pycache)
    expected_sentinel_raw = (
        json.dumps(
            {
                "schema_version": "qrh-exact-runtime-pycache-sentinel/v1",
                **sentinel_identity,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    try:
        info = pycache_sentinel.lstat()
        reparse = stat.S_ISLNK(info.st_mode) or bool(
            getattr(info, "st_file_attributes", 0) & 0x400
        )
        sentinel_raw = pycache_sentinel.read_bytes()
    except OSError as error:
        raise ExactRuntimeEntryError(
            "exact runtime pycache sentinel is unavailable"
        ) from error
    if (
        reparse
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or sentinel_raw != expected_sentinel_raw
        or os.path.isdir(pycache_sentinel)
    ):
        raise ExactRuntimeEntryError(
            "exact runtime pycache sentinel is not closed"
        )

    from .local_windows_writer_lease_holder import ProductionWindowsWriterLeaseHolder

    holder = ProductionWindowsWriterLeaseHolder.load_exact_d()
    if steady:
        from .local_exact_runtime_admission import (
            ProductionExactRuntimeAdmissionGate,
        )

        gate = ProductionExactRuntimeAdmissionGate.load_from_service_stdin()
        lease = holder.acquire_steady_exact_d(gate)
        try:
            from .local_exact_runtime_process import run_steady_exact_runtime

            return run_steady_exact_runtime(lease, gate)
        finally:
            lease._finalize_for_process_exit()
    from .local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity

    identity = ExactRuntimeLeaseIdentity(**values)
    lease = holder.acquire_exact_d(identity)
    try:
        from .local_exact_runtime_process import run_exact_runtime

        return run_exact_runtime(lease)
    finally:
        lease._finalize_for_process_exit()


if __name__ == "__main__":
    raise SystemExit(main())
