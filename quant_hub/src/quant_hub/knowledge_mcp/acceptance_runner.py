"""Fake-only, append-only runner for public MCP acceptance fixtures.

Real Codex execution is intentionally disabled.  The runner writes an atomic
dispatch intent before invoking a caller-provided in-process fake transport and
an atomic completion record afterwards.  Evaluators consume both exact ledger
files, so neither timestamps nor prompt/config/trace bindings are taken from a
mutable JSONL field.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Callable, Mapping

from quant_hub.knowledge.contracts import canonical_json

from .evaluation import (
    ACCEPTANCE_FAKE_DISPATCH_SCHEMA,
    CODEX_TRACE_MAX_BYTES,
    _load_preregistration_ledger,
    _utc_now,
    _write_new_bytes,
    validate_acceptance_preregistration_bytes,
)


@dataclass(frozen=True, slots=True)
class FakeArmRun:
    trace_bytes: bytes
    intent_bytes: bytes
    completion_bytes: bytes


def fake_dispatch_paths(
    ledger_root: Path, *, run_id: str, case_id: str, arm: str
) -> tuple[Path, Path]:
    key = canonical_json({"run_id": run_id, "case_id": case_id, "arm": arm})
    name = hashlib.sha256(key.encode("utf-8")).hexdigest()
    root = Path(ledger_root)
    return root / f"{name}.intent.json", root / f"{name}.complete.json"


def run_fake_acceptance_arm(
    *,
    preregistration: bytes,
    preregistration_ledger: Path,
    dispatch_ledger_root: Path,
    case_id: str,
    arm: str,
    prompt_bytes: bytes,
    config_bytes: bytes,
    fake_transport: Callable[[bytes, str], bytes],
) -> FakeArmRun:
    """Run exactly one public fake arm; all real transports remain disabled."""

    if arm not in {"assisted", "no_mcp"} or not callable(fake_transport):
        raise ValueError("fake acceptance dispatch input is invalid")
    registered = validate_acceptance_preregistration_bytes(preregistration)
    ledger = _load_preregistration_ledger(
        preregistration_ledger, preregistration
    )
    definitions: Mapping[str, Mapping[str, object]] = {
        str(row["case_id"]): row for row in registered["cases"]
    }
    definition = definitions.get(case_id)
    if (
        definition is None
        or not isinstance(prompt_bytes, bytes)
        or len(prompt_bytes) != definition["prompt_bytes"]
        or hashlib.sha256(prompt_bytes).hexdigest() != definition["prompt_sha256"]
        or not isinstance(config_bytes, bytes)
        or len(config_bytes) != registered["config_bytes"]
        or hashlib.sha256(config_bytes).hexdigest() != registered["config_sha256"]
    ):
        raise ValueError("fake acceptance dispatch differs from preregistration")
    intent_path, completion_path = fake_dispatch_paths(
        dispatch_ledger_root,
        run_id=str(registered["run_id"]),
        case_id=case_id,
        arm=arm,
    )
    # A completion without its intent is an inconsistent/ambiguous prior
    # dispatch.  Refuse before invoking even the fake transport.
    if completion_path.exists():
        raise FileExistsError(completion_path)
    dispatched_at = _utc_now()
    if dispatched_at <= str(ledger["registered_at"]):
        raise ValueError("fake dispatch did not follow preregistration ledger")
    intent = canonical_json(
        {
            "schema_version": ACCEPTANCE_FAKE_DISPATCH_SCHEMA,
            "record_type": "INTENT",
            "runner": "FAKE_ONLY_REAL_CODEX_DISABLED",
            "run_id": registered["run_id"],
            "case_id": case_id,
            "arm": arm,
            "dispatched_at": dispatched_at,
            "preregistration_ledger_sha256": hashlib.sha256(
                canonical_json(dict(ledger)).encode("utf-8")
            ).hexdigest(),
            "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
            "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        }
    ).encode("utf-8")
    _write_new_bytes(intent_path, intent)
    trace_bytes = fake_transport(prompt_bytes, arm)
    if (
        not isinstance(trace_bytes, bytes)
        or not trace_bytes
        or len(trace_bytes) > CODEX_TRACE_MAX_BYTES
    ):
        raise ValueError("fake transport did not return raw trace bytes")
    completed_at = _utc_now()
    completion = canonical_json(
        {
            "schema_version": ACCEPTANCE_FAKE_DISPATCH_SCHEMA,
            "record_type": "COMPLETE",
            "runner": "FAKE_ONLY_REAL_CODEX_DISABLED",
            "run_id": registered["run_id"],
            "case_id": case_id,
            "arm": arm,
            "dispatched_at": dispatched_at,
            "completed_at": completed_at,
            "intent_sha256": hashlib.sha256(intent).hexdigest(),
            "trace_bytes": len(trace_bytes),
            "trace_sha256": hashlib.sha256(trace_bytes).hexdigest(),
        }
    ).encode("utf-8")
    _write_new_bytes(completion_path, completion)
    return FakeArmRun(trace_bytes, intent, completion)


__all__ = ["FakeArmRun", "fake_dispatch_paths", "run_fake_acceptance_arm"]
