"""Append-only fake fixtures and real ``codex exec --json`` MCP acceptance.

Both runners write an atomic dispatch intent before execution and an atomic
completion afterwards.  The real runner additionally streams stdout directly
to an exclusive raw JSONL file; it never uses a shell and sends the exact bound
prompt through stdin.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Callable, Mapping
from uuid import uuid4

from quant_hub.knowledge.contracts import canonical_json

from .acceptance_contracts import (
    REAL_ACCEPTANCE_INPUT_SCHEMA,
    REAL_CODEX_RUNNER,
    assert_canonical_no_reparse_path,
    build_real_codex_command,
    build_real_request_material,
    observe_static_provenance,
    observe_windows_descendant_image,
    observe_windows_process_image,
    pin_runtime_closure,
    real_dispatch_paths,
    real_prompt_path,
    stable_read_file,
    validate_arm_command_difference,
    validate_evidence_root,
    validate_process_observation,
    validate_real_codex_launch_config_bytes,
)
from .evaluation import (
    ACCEPTANCE_FAKE_DISPATCH_SCHEMA,
    ACCEPTANCE_REAL_DISPATCH_SCHEMA,
    CODEX_TRACE_MAX_BYTES,
    _load_preregistration_ledger,
    _reject_duplicate_json_keys,
    _utc_now,
    _write_new_bytes,
    load_codex_tool_trace_bytes,
    record_acceptance_preregistration,
    validate_acceptance_preregistration_bytes,
)


@dataclass(frozen=True, slots=True)
class FakeArmRun:
    trace_bytes: bytes
    intent_bytes: bytes
    completion_bytes: bytes


@dataclass(frozen=True, slots=True)
class RealArmRun:
    trace_bytes: bytes
    intent_bytes: bytes
    completion_bytes: bytes
    status: str
    trace_path: Path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


_INPUT_FILE_LIMIT = 2 * 1024 * 1024
_STDERR_MAX_BYTES = 1024 * 1024


def acceptance_evidence_inventory(evidence_root: Path) -> dict[str, dict[str, object]]:
    """Return a stable, closed inventory and reject links/reparse/extra directories."""

    root = assert_canonical_no_reparse_path(
        evidence_root, kind="acceptance evidence root"
    )
    if not root.is_dir():
        raise ValueError("acceptance evidence root must be a directory")
    rows: dict[str, dict[str, object]] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        before_names = sorted(entry.name for entry in os.scandir(directory))
        for name in before_names:
            child = directory / name
            relative = child.relative_to(root).as_posix()
            resolved = assert_canonical_no_reparse_path(
                child, kind=f"acceptance evidence entry {relative}"
            )
            if resolved.is_dir():
                if relative not in {"cases", "dispatch"}:
                    raise ValueError("acceptance evidence contains an unexpected directory")
                pending.append(resolved)
                continue
            maximum = CODEX_TRACE_MAX_BYTES if relative.endswith(".trace.jsonl") else _INPUT_FILE_LIMIT
            payload = stable_read_file(
                resolved, kind=f"acceptance evidence file {relative}", maximum=maximum
            )
            rows[relative] = {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        after_names = sorted(entry.name for entry in os.scandir(directory))
        if before_names != after_names:
            raise ValueError("acceptance evidence inventory changed while observed")
    return dict(sorted(rows.items()))


def expected_acceptance_paths(
    registered: Mapping[str, object], *, include_dispatch: bool, include_receipt: bool
) -> set[str]:
    expected = {
        "preregistration.json",
        "preregistration.ledger.json",
        "launch-config.json",
        "input-manifest.json",
    }
    run_id = str(registered["run_id"])
    for definition in registered["cases"]:
        case_id = str(definition["case_id"])
        expected.add(
            real_prompt_path(Path("."), run_id=run_id, case_id=case_id).as_posix()
        )
        if include_dispatch:
            for arm in ("assisted", "no_mcp"):
                for path in real_dispatch_paths(
                    Path("dispatch"), run_id=run_id, case_id=case_id, arm=arm
                ):
                    expected.add(path.as_posix())
    if include_receipt:
        expected.add("campaign-receipt.json")
    return expected


def _input_paths(root: Path) -> tuple[Path, Path, Path, Path]:
    root = Path(root)
    return (
        root / "preregistration.json",
        root / "preregistration.ledger.json",
        root / "launch-config.json",
        root / "input-manifest.json",
    )


def _commit_staged_directory(staging: Path, destination: Path) -> None:
    """Publish a complete staged root without replacing an existing target."""

    if destination.exists():
        raise FileExistsError(destination)
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file = kernel32.MoveFileExW
        move_file.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
        move_file.restype = wintypes.BOOL
        if not move_file(str(staging), str(destination), 0x00000008):
            error = ctypes.get_last_error()
            if destination.exists():
                raise FileExistsError(destination)
            raise OSError(error, "staged acceptance root commit failed")
        return
    os.rename(staging, destination)
    descriptor = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def record_real_acceptance_inputs(
    *,
    preregistration: bytes,
    config_bytes: bytes,
    prompts: Mapping[str, bytes],
    evidence_root: Path,
) -> bytes:
    """Persist the complete prereg/config/prompt input closure before dispatch."""

    registered = validate_acceptance_preregistration_bytes(preregistration)
    config = validate_real_codex_launch_config_bytes(
        config_bytes, server_name=str(registered["server_name"])
    )
    if (
        len(config_bytes) != registered["config_bytes"]
        or hashlib.sha256(config_bytes).hexdigest() != registered["config_sha256"]
    ):
        raise ValueError("real acceptance config differs from preregistration")
    evidence_root = validate_evidence_root(config, evidence_root, must_be_new=True)
    validate_arm_command_difference(
        config,
        server_name=str(registered["server_name"]),
        model=str(registered["model"]),
    )
    registration_pins = pin_runtime_closure(config)
    try:
        initial_provenance = observe_static_provenance(config)
        definitions = {str(row["case_id"]): row for row in registered["cases"]}
        if set(prompts) != set(definitions):
            raise ValueError("real acceptance prompts differ from preregistration")
        rows: list[dict[str, object]] = []
        for case_id in (str(row["case_id"]) for row in registered["cases"]):
            prompt = prompts[case_id]
            definition = definitions[case_id]
            if (
                not isinstance(prompt, bytes)
                or len(prompt) != definition["prompt_bytes"]
                or hashlib.sha256(prompt).hexdigest() != definition["prompt_sha256"]
            ):
                raise ValueError("real acceptance prompt differs from preregistration")
            rows.append(
                {
                    "case_id": case_id,
                    "prompt_bytes": len(prompt),
                    "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
                }
            )
        staging = evidence_root.parent / f".{evidence_root.name}.staging-{uuid4().hex}"
        try:
            os.mkdir(staging, 0o700)
            preregistration_path, ledger_path, config_path, manifest_path = _input_paths(
                staging
            )
            _write_new_bytes(preregistration_path, preregistration)
            ledger = record_acceptance_preregistration(
                preregistration, ledger_path=ledger_path
            )
            _write_new_bytes(config_path, config_bytes)
            for row in rows:
                prompt_path = real_prompt_path(
                    staging,
                    run_id=str(registered["run_id"]),
                    case_id=str(row["case_id"]),
                )
                _write_new_bytes(prompt_path, prompts[str(row["case_id"])])
            manifest = canonical_json(
                {
                    "schema_version": REAL_ACCEPTANCE_INPUT_SCHEMA,
                    "run_id": registered["run_id"],
                    "preregistration_sha256": hashlib.sha256(preregistration).hexdigest(),
                    "preregistration_ledger_sha256": hashlib.sha256(ledger).hexdigest(),
                    "config_bytes": len(config_bytes),
                    "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
                    "initial_provenance": initial_provenance,
                    "cases": rows,
                }
            ).encode("utf-8")
            _write_new_bytes(manifest_path, manifest)
            actual = set(acceptance_evidence_inventory(staging))
            expected = expected_acceptance_paths(
                registered, include_dispatch=False, include_receipt=False
            )
            if actual != expected:
                raise ValueError("staged acceptance input inventory is not closed")
            _commit_staged_directory(staging, evidence_root)
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging)
            raise
        if set(acceptance_evidence_inventory(evidence_root)) != expected:
            raise ValueError("committed acceptance input inventory differs")
        return manifest
    finally:
        registration_pins.close()


def load_real_acceptance_inputs(
    evidence_root: Path,
) -> tuple[bytes, Path, bytes, dict[str, bytes]]:
    """Replay and verify the exact persisted input closure."""

    evidence_root = assert_canonical_no_reparse_path(
        evidence_root, kind="acceptance evidence root"
    )
    inventory_before = acceptance_evidence_inventory(evidence_root)
    preregistration_path, ledger_path, config_path, manifest_path = _input_paths(evidence_root)
    try:
        preregistration = stable_read_file(
            preregistration_path, kind="acceptance preregistration", maximum=_INPUT_FILE_LIMIT
        )
        config_bytes = stable_read_file(
            config_path, kind="acceptance launch config", maximum=_INPUT_FILE_LIMIT
        )
        manifest_bytes = stable_read_file(
            manifest_path, kind="acceptance input manifest", maximum=_INPUT_FILE_LIMIT
        )
        manifest = json.loads(
            manifest_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("real acceptance input closure is unreadable") from error
    registered = validate_acceptance_preregistration_bytes(preregistration)
    ledger = _load_preregistration_ledger(ledger_path, preregistration)
    config = validate_real_codex_launch_config_bytes(
        config_bytes, server_name=str(registered["server_name"])
    )
    validate_evidence_root(config, evidence_root, must_be_new=False)
    validate_arm_command_difference(
        config,
        server_name=str(registered["server_name"]),
        model=str(registered["model"]),
    )
    fields = {
        "schema_version", "run_id", "preregistration_sha256",
        "preregistration_ledger_sha256", "config_bytes", "config_sha256",
        "initial_provenance", "cases",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != fields
        or manifest.get("schema_version") != REAL_ACCEPTANCE_INPUT_SCHEMA
        or canonical_json(manifest).encode("utf-8") != manifest_bytes
        or manifest.get("run_id") != registered["run_id"]
        or manifest.get("preregistration_sha256")
        != hashlib.sha256(preregistration).hexdigest()
        or manifest.get("preregistration_ledger_sha256")
        != hashlib.sha256(canonical_json(dict(ledger)).encode("utf-8")).hexdigest()
        or manifest.get("config_bytes") != len(config_bytes)
        or manifest.get("config_sha256") != hashlib.sha256(config_bytes).hexdigest()
        or manifest.get("initial_provenance") != observe_static_provenance(config)
        or not isinstance(manifest.get("cases"), list)
    ):
        raise ValueError("real acceptance input manifest binding is invalid")
    definitions = {str(row["case_id"]): row for row in registered["cases"]}
    prompts: dict[str, bytes] = {}
    expected_rows: list[dict[str, object]] = []
    for definition in registered["cases"]:
        case_id = str(definition["case_id"])
        try:
            prompt = stable_read_file(
                real_prompt_path(
                    evidence_root,
                    run_id=str(registered["run_id"]),
                    case_id=case_id,
                ),
                kind=f"acceptance prompt {case_id}",
                maximum=128 * 1024,
            )
        except OSError as error:
            raise ValueError("real acceptance prompt evidence is unreadable") from error
        row = {
            "case_id": case_id,
            "prompt_bytes": len(prompt),
            "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
        }
        if (
            row["prompt_bytes"] != definitions[case_id]["prompt_bytes"]
            or row["prompt_sha256"] != definitions[case_id]["prompt_sha256"]
        ):
            raise ValueError("real acceptance prompt evidence binding is invalid")
        prompts[case_id] = prompt
        expected_rows.append(row)
    if manifest["cases"] != expected_rows:
        raise ValueError("real acceptance case manifest differs")
    allowed = expected_acceptance_paths(
        registered, include_dispatch=True, include_receipt=True
    ) | {"campaign-failure.json"}
    actual = set(inventory_before)
    required_inputs = expected_acceptance_paths(
        registered, include_dispatch=False, include_receipt=False
    )
    if not required_inputs.issubset(actual) or not actual.issubset(allowed):
        raise ValueError("acceptance evidence inventory is not closed")
    if inventory_before != acceptance_evidence_inventory(evidence_root):
        raise ValueError("acceptance evidence changed while loading inputs")
    return preregistration, ledger_path, config_bytes, prompts


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


def run_real_acceptance_arm(
    *,
    preregistration: bytes,
    preregistration_ledger: Path,
    dispatch_ledger_root: Path,
    case_id: str,
    arm: str,
    prompt_bytes: bytes,
    config_bytes: bytes,
) -> RealArmRun:
    """Execute one Codex arm with bounded streams and live Windows provenance."""

    if arm not in {"assisted", "no_mcp"}:
        raise ValueError("real acceptance arm is invalid")
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
        raise ValueError("real acceptance dispatch differs from preregistration")
    config = validate_real_codex_launch_config_bytes(
        config_bytes, server_name=str(registered["server_name"])
    )
    resolved_working_directory = assert_canonical_no_reparse_path(
        Path(str(config["working_directory"])), kind="Codex working directory"
    )
    if not resolved_working_directory.is_dir():
        raise ValueError("Codex working directory is invalid")
    command = build_real_codex_command(
        config,
        server_name=str(registered["server_name"]),
        model=str(registered["model"]),
        arm=arm,
    )
    request = build_real_request_material(
        run_id=str(registered["run_id"]),
        case_id=case_id,
        arm=arm,
        authority_identity=registered["authority_identity"],
        server_name=str(registered["server_name"]),
        model=str(registered["model"]),
        prompt_bytes=prompt_bytes,
        config_bytes=config_bytes,
        command=command,
    )
    request_sha256 = hashlib.sha256(
        canonical_json(request).encode("utf-8")
    ).hexdigest()
    runtime_pins = pin_runtime_closure(config)
    provenance_before = observe_static_provenance(config)
    intent_path, trace_path, completion_path = real_dispatch_paths(
        dispatch_ledger_root,
        run_id=str(registered["run_id"]),
        case_id=case_id,
        arm=arm,
    )
    if completion_path.exists() or trace_path.exists():
        raise FileExistsError(completion_path if completion_path.exists() else trace_path)
    dispatched_at = _utc_now()
    if dispatched_at <= str(ledger["registered_at"]):
        raise ValueError("real dispatch did not follow preregistration ledger")
    intent = canonical_json(
        {
            "schema_version": ACCEPTANCE_REAL_DISPATCH_SCHEMA,
            "record_type": "INTENT",
            "runner": REAL_CODEX_RUNNER,
            "run_id": registered["run_id"],
            "case_id": case_id,
            "arm": arm,
            "dispatched_at": dispatched_at,
            "preregistration_sha256": hashlib.sha256(preregistration).hexdigest(),
            "preregistration_ledger_sha256": hashlib.sha256(
                canonical_json(dict(ledger)).encode("utf-8")
            ).hexdigest(),
            "request": request,
            "request_sha256": request_sha256,
            "provenance_before": provenance_before,
        }
    ).encode("utf-8")
    _write_new_bytes(intent_path, intent)

    status = "launch_failed"
    exit_code: int | None = None
    process_observation: dict[str, object] | None = None
    mcp_process_observation: dict[str, object] = {
        "launcher": None,
        "python": None,
    }
    provenance_during: dict[str, object] | None = None
    provenance_after: dict[str, object] | None = None
    stderr_state: dict[str, object] = {
        "bytes": 0,
        "digest": hashlib.sha256(),
        "overflow": False,
        "error": None,
    }
    stdout_state: dict[str, object] = {
        "bytes": 0,
        "digest": hashlib.sha256(),
        "overflow": False,
        "error": None,
    }
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(trace_path, flags, 0o600)
    process: subprocess.Popen[bytes] | None = None
    threads: list[threading.Thread] = []
    monitor_stop = threading.Event()
    monitor_state: dict[str, object] = {
        "launcher": None,
        "python": None,
        "error": None,
    }

    def monitor_mcp_process() -> None:
        try:
            while not monitor_stop.is_set():
                for name, field in (
                    ("launcher", "command"),
                    ("python", "python_executable"),
                ):
                    if monitor_state[name] is None:
                        monitor_state[name] = observe_windows_descendant_image(
                            int(getattr(process, "pid")),
                            Path(str(config["mcp_server"][field])),
                        )
                if arm == "assisted" and all(
                    monitor_state[name] is not None
                    for name in ("launcher", "python")
                ):
                    return
                time.sleep(0.05)
            for name, field in (
                ("launcher", "command"),
                ("python", "python_executable"),
            ):
                if monitor_state[name] is None:
                    monitor_state[name] = observe_windows_descendant_image(
                        int(getattr(process, "pid")),
                        Path(str(config["mcp_server"][field])),
                    )
        except BaseException as error:
            monitor_state["error"] = repr(error)

    def pump(source, *, sink, limit: int, state: dict[str, object]) -> None:
        try:
            while True:
                chunk = source.read(64 * 1024)
                if not chunk:
                    break
                current = int(state["bytes"])
                state["bytes"] = current + len(chunk)
                state["digest"].update(chunk)
                remaining = max(0, limit - current)
                if sink is not None and remaining:
                    sink.write(chunk[:remaining])
                if len(chunk) > remaining:
                    state["overflow"] = True
                    if process is not None:
                        try:
                            process.kill()
                        except OSError:
                            pass
        except BaseException as error:
            state["error"] = repr(error)
            if process is not None:
                try:
                    process.kill()
                except OSError:
                    pass

    try:
        with os.fdopen(descriptor, "wb", closefd=True) as trace_handle:
            try:
                process = subprocess.Popen(
                    list(command),
                    cwd=str(resolved_working_directory),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                )
                process_observation = observe_windows_process_image(
                    getattr(process, "pid", None)
                )
                provenance_during = observe_static_provenance(config)
                validate_process_observation(
                    config, process_observation, provenance_during
                )
                if provenance_before != provenance_during:
                    raise ValueError("acceptance provenance changed before process input")
                if process.stdout is None or process.stderr is None or process.stdin is None:
                    raise ValueError("Codex subprocess pipes are unavailable")
                threads = [
                    threading.Thread(
                        target=pump,
                        kwargs={
                            "source": process.stdout,
                            "sink": trace_handle,
                            "limit": CODEX_TRACE_MAX_BYTES,
                            "state": stdout_state,
                        },
                        daemon=True,
                    ),
                    threading.Thread(
                        target=pump,
                        kwargs={
                            "source": process.stderr,
                            "sink": None,
                            "limit": _STDERR_MAX_BYTES,
                            "state": stderr_state,
                        },
                        daemon=True,
                    ),
                ]
                monitor_thread = threading.Thread(target=monitor_mcp_process, daemon=True)
                monitor_thread.start()
                for thread in threads:
                    thread.start()
                process.stdin.write(prompt_bytes)
                process.stdin.flush()
                process.stdin.close()
                try:
                    exit_code = process.wait(timeout=int(config["timeout_seconds"]))
                except subprocess.TimeoutExpired:
                    process.kill()
                    exit_code = process.wait(timeout=30)
                    status = "timeout"
                for thread in threads:
                    thread.join(timeout=30)
                monitor_stop.set()
                monitor_thread.join(timeout=30)
                mcp_process_observation = {
                    "launcher": monitor_state["launcher"],
                    "python": monitor_state["python"],
                }
                if any(thread.is_alive() for thread in threads):
                    status = "stream_shutdown_failed"
                    process.kill()
                elif stdout_state["error"] is not None or stderr_state["error"] is not None:
                    status = "stream_failed"
                elif stdout_state["overflow"] or stderr_state["overflow"]:
                    status = "output_limit_exceeded"
                elif monitor_thread.is_alive() or monitor_state["error"] is not None:
                    status = "mcp_process_observer_failed"
                elif arm == "assisted" and any(
                    mcp_process_observation[name] is None
                    for name in ("launcher", "python")
                ):
                    status = "mcp_process_provenance_failed"
                elif arm == "no_mcp" and any(
                    mcp_process_observation[name] is not None
                    for name in ("launcher", "python")
                ):
                    status = "mcp_process_provenance_failed"
                elif status != "timeout":
                    status = "completed" if exit_code == 0 else "process_failed"
            except (AttributeError, OSError, ValueError):
                monitor_stop.set()
                if process is not None:
                    try:
                        process.kill()
                        exit_code = process.wait(timeout=30)
                    except (AttributeError, OSError, subprocess.TimeoutExpired):
                        pass
                    status = "provenance_failed"
                else:
                    status = "launch_failed"
            try:
                provenance_after = observe_static_provenance(config)
                if (
                    status == "completed"
                    and (
                        provenance_after != provenance_before
                        or provenance_after != provenance_during
                    )
                ):
                    status = "provenance_changed"
            except ValueError:
                provenance_after = None
                if status == "completed":
                    status = "provenance_failed"
            if process is not None:
                for stream in (
                    getattr(process, "stdout", None),
                    getattr(process, "stderr", None),
                    getattr(process, "stdin", None),
                ):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass
            if process is None:
                status = "launch_failed"
            trace_handle.flush()
            os.fsync(trace_handle.fileno())
    except BaseException:
        raise
    trace_bytes = stable_read_file(
        trace_path, kind="Codex raw JSONL trace", maximum=CODEX_TRACE_MAX_BYTES
    )
    if status == "completed" and (
        not trace_bytes or len(trace_bytes) > CODEX_TRACE_MAX_BYTES
    ):
        status = "trace_invalid"
    elif status == "completed":
        try:
            load_codex_tool_trace_bytes(
                trace_bytes, server_name=str(registered["server_name"])
            )
        except ValueError:
            status = "trace_invalid"
    try:
        runtime_pins.close()
    except ValueError:
        status = "runtime_pin_close_failed"
    completed_at = _utc_now()
    completion = canonical_json(
        {
            "schema_version": ACCEPTANCE_REAL_DISPATCH_SCHEMA,
            "record_type": "COMPLETE",
            "runner": REAL_CODEX_RUNNER,
            "run_id": registered["run_id"],
            "case_id": case_id,
            "arm": arm,
            "dispatched_at": dispatched_at,
            "completed_at": completed_at,
            "intent_sha256": hashlib.sha256(intent).hexdigest(),
            "request_sha256": request_sha256,
            "status": status,
            "exit_code": exit_code,
            "trace_bytes": len(trace_bytes),
            "trace_sha256": hashlib.sha256(trace_bytes).hexdigest(),
            "stderr_bytes": int(stderr_state["bytes"]),
            "stderr_sha256": stderr_state["digest"].hexdigest(),
            "process_observation": process_observation,
            "mcp_process_observation": mcp_process_observation,
            "provenance_during": provenance_during,
            "provenance_after": provenance_after,
        }
    ).encode("utf-8")
    _write_new_bytes(completion_path, completion)
    return RealArmRun(trace_bytes, intent, completion, status, trace_path)


__all__ = [
    "FakeArmRun",
    "RealArmRun",
    "acceptance_evidence_inventory",
    "expected_acceptance_paths",
    "fake_dispatch_paths",
    "load_real_acceptance_inputs",
    "real_dispatch_paths",
    "record_real_acceptance_inputs",
    "run_fake_acceptance_arm",
    "run_real_acceptance_arm",
]
