"""Closed contracts and OS provenance for real Codex MCP acceptance."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time
from typing import Mapping, Sequence

from quant_hub.knowledge.contracts import canonical_json


REAL_CODEX_LAUNCH_SCHEMA = "qrh-mcp-real-codex-launch/v2-process-provenance"
REAL_ACCEPTANCE_PROMPTS_SCHEMA = "qrh-mcp-real-acceptance-prompts/v1"
REAL_ACCEPTANCE_INPUT_SCHEMA = "qrh-mcp-real-acceptance-input/v2-staged-closure"
REAL_CODEX_RUNNER = "REAL_CODEX_EXEC"
NON_QUALIFYING_CODEX_RUNNER = "CODEX_EXEC_PROVENANCE_UNVERIFIED"
REAL_CODEX_EVIDENCE_REPLAY_AUTHORITY = (
    "REAL_CODEX_EVIDENCE_REPLAY_NON_AUTHORITATIVE"
)
PUBLIC_SYNTHETIC_ACCEPTANCE_AUTHORITY = (
    "PUBLIC_SYNTHETIC_NON_QUALIFYING_GATE"
)
PRODUCTION_AUDIT_ROOT = Path(r"D:\quant\quant_platform\audit")
_WINDOWS_SCRIPT_SUFFIXES = {".bat", ".cmd", ".ps1"}
# The signed native Codex 0.151 Windows image is about 300 MiB.  Hash it by
# streaming, but retain a finite ceiling so a path cannot become an unbounded
# provenance read.
_MAX_STATIC_FILE_BYTES = 512 * 1024 * 1024


def _reject_duplicate_json_keys(
    pairs: Sequence[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key:{key}")
        value[key] = item
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_thumbprint(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) in {40, 64}
        and all(character in "0123456789ABCDEF" for character in value)
    )


def _normal_path(value: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(value)))


def _path_is_reparse(status: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(status, "st_file_attributes", 0) & marker)


def assert_canonical_no_reparse_path(
    path: Path, *, kind: str, allow_missing_leaf: bool = False
) -> Path:
    """Resolve one path without accepting symlink/junction/reparse components."""

    path = Path(path)
    if not path.is_absolute():
        raise ValueError(f"{kind} must be absolute")
    parts = path.parts
    current = Path(parts[0])
    for index, part in enumerate(parts[1:], 1):
        current /= part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            if allow_missing_leaf and index == len(parts) - 1:
                break
            raise ValueError(f"{kind} is unavailable") from None
        except OSError as error:
            raise ValueError(f"{kind} is unreadable") from error
        if stat.S_ISLNK(status.st_mode) or _path_is_reparse(status):
            raise ValueError(f"{kind} contains a reparse component")
    try:
        resolved = (
            path.parent.resolve(strict=True) / path.name
            if allow_missing_leaf and not path.exists()
            else path.resolve(strict=True)
        )
    except OSError as error:
        raise ValueError(f"{kind} is unavailable") from error
    if _normal_path(path) != _normal_path(resolved):
        raise ValueError(f"{kind} is non-canonical")
    return resolved


def _stable_file_observation(path: Path, *, kind: str) -> dict[str, object]:
    resolved = assert_canonical_no_reparse_path(path, kind=kind)
    digest = hashlib.sha256()
    total = 0
    try:
        with resolved.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError(f"{kind} must be a single-link regular file")
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                total += len(chunk)
                if total > _MAX_STATIC_FILE_BYTES:
                    raise ValueError(f"{kind} exceeds the accepted size")
                digest.update(chunk)
            after = os.fstat(handle.fileno())
            path_status = os.stat(resolved, follow_symlinks=False)
    except OSError as error:
        raise ValueError(f"{kind} is unreadable") from error
    stable_fields = (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns"
    )
    if any(getattr(before, name) != getattr(after, name) for name in stable_fields):
        raise ValueError(f"{kind} changed while observed")
    if not os.path.samestat(after, path_status) or after.st_size != total:
        raise ValueError(f"{kind} path identity changed while observed")
    return {
        "path": str(resolved),
        "sha256": digest.hexdigest(),
        "bytes": total,
        "file_identity": f"{after.st_dev}:{after.st_ino}",
        "mtime_ns": after.st_mtime_ns,
    }


def stable_read_file(path: Path, *, kind: str, maximum: int) -> bytes:
    resolved = assert_canonical_no_reparse_path(path, kind=kind)
    try:
        with resolved.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError(f"{kind} must be a single-link regular file")
            payload = handle.read(maximum + 1)
            after = os.fstat(handle.fileno())
            path_status = os.stat(resolved, follow_symlinks=False)
    except OSError as error:
        raise ValueError(f"{kind} is unreadable") from error
    if len(payload) > maximum:
        raise ValueError(f"{kind} exceeds the accepted size")
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
    if (
        any(getattr(before, name) != getattr(after, name) for name in stable_fields)
        or not os.path.samestat(after, path_status)
        or after.st_size != len(payload)
    ):
        raise ValueError(f"{kind} changed while read")
    return payload


def _directory_observation(path: Path, *, kind: str) -> dict[str, object]:
    resolved = assert_canonical_no_reparse_path(path, kind=kind)
    status = os.stat(resolved, follow_symlinks=False)
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError(f"{kind} must be a directory")
    return {
        "path": str(resolved),
        "file_identity": f"{status.st_dev}:{status.st_ino}",
    }


def _summarize_codex_non_user_layers(
    layers: object,
) -> list[dict[str, object]]:
    if not isinstance(layers, list):
        raise ValueError("Codex config observer returned no layer stack")
    summaries: list[dict[str, object]] = []
    for layer in layers:
        if (
            not isinstance(layer, dict)
            or not isinstance(layer.get("name"), dict)
            or not isinstance(layer["name"].get("type"), str)
            or not isinstance(layer.get("config"), dict)
            or not isinstance(layer.get("version"), str)
        ):
            raise ValueError("Codex config layer is invalid")
        layer_type = layer["name"]["type"]
        if layer_type == "user":
            continue
        disabled = layer.get("disabledReason") is not None
        servers = layer["config"].get("mcp_servers", {})
        if not isinstance(servers, dict):
            raise ValueError("Codex non-user MCP layer is invalid")
        if not disabled and servers:
            raise ValueError("Codex non-user config contributes an ambient MCP server")
        if not disabled and any(
            layer["config"].get(name)
            for name in ("apps", "plugins", "plugin_marketplaces", "marketplaces")
        ):
            raise ValueError("Codex non-user config contributes an ambient plugin/app")
        summaries.append(
            {
                "type": layer_type,
                "version": layer["version"],
                "disabled": disabled,
                "config_sha256": hashlib.sha256(
                    canonical_json(layer["config"]).encode("utf-8")
                ).hexdigest(),
            }
        )
    return summaries


def _observe_codex_non_user_layers(
    config: Mapping[str, object], codex_static: Mapping[str, object]
) -> dict[str, object]:
    """Read Codex's effective layer stack and reject ambient non-user MCPs."""

    process: subprocess.Popen[bytes] | None = None
    condition = threading.Condition()
    responses: dict[int, Mapping[str, object]] = {}
    state: dict[str, object] = {
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "overflow": False,
        "error": False,
    }

    def stdout_pump(source) -> None:
        pending = bytearray()
        try:
            while True:
                reader = getattr(source, "read1", source.read)
                chunk = reader(64 * 1024)
                if not chunk:
                    break
                state["stdout_bytes"] = int(state["stdout_bytes"]) + len(chunk)
                if state["stdout_bytes"] > 8 * 1024 * 1024:
                    state["overflow"] = True
                    if process is not None:
                        process.kill()
                    return
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, remainder = pending.partition(b"\n")
                    pending = bytearray(remainder)
                    if not line.strip():
                        continue
                    row = json.loads(
                        line.decode("utf-8", errors="strict"),
                        object_pairs_hook=_reject_duplicate_json_keys,
                    )
                    if isinstance(row, dict) and row.get("id") in {0, 1}:
                        with condition:
                            responses[int(row["id"])] = row
                            condition.notify_all()
            if pending.strip():
                raise ValueError("Codex config observer emitted a partial JSON line")
        except BaseException:
            state["error"] = True
            if process is not None:
                try:
                    process.kill()
                except OSError:
                    pass
            with condition:
                condition.notify_all()

    def stderr_pump(source) -> None:
        try:
            while True:
                reader = getattr(source, "read1", source.read)
                chunk = reader(64 * 1024)
                if not chunk:
                    break
                state["stderr_bytes"] = int(state["stderr_bytes"]) + len(chunk)
                if state["stderr_bytes"] > 1024 * 1024:
                    state["overflow"] = True
                    if process is not None:
                        process.kill()
                    return
        except BaseException:
            state["error"] = True
            if process is not None:
                try:
                    process.kill()
                except OSError:
                    pass
            with condition:
                condition.notify_all()

    def send(value: Mapping[str, object]) -> None:
        if process is None or process.stdin is None:
            raise ValueError("Codex config observer stdin is unavailable")
        process.stdin.write(canonical_json(dict(value)).encode("utf-8") + b"\n")
        process.stdin.flush()

    def wait_response(identifier: int) -> Mapping[str, object]:
        deadline = time.monotonic() + 20
        with condition:
            while identifier not in responses and not state["error"]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                condition.wait(timeout=remaining)
        response = responses.get(identifier)
        if response is None or response.get("error") is not None:
            raise ValueError("Codex effective config observation failed")
        return response

    try:
        process = subprocess.Popen(
            [
                str(config["codex_executable"]),
                "app-server",
                "--stdio",
                "--strict-config",
            ],
            cwd=str(config["working_directory"]),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        live = observe_windows_process_image(getattr(process, "pid", None))
        if live.get("image") != codex_static:
            raise ValueError("Codex config observer process image differs")
        if process.stdout is None or process.stderr is None:
            raise ValueError("Codex config observer pipes are unavailable")
        threads = (
            threading.Thread(target=stdout_pump, args=(process.stdout,), daemon=True),
            threading.Thread(target=stderr_pump, args=(process.stderr,), daemon=True),
        )
        for thread in threads:
            thread.start()
        send(
            {
                "method": "initialize",
                "id": 0,
                "params": {
                    "clientInfo": {
                        "name": "quant_hub_acceptance",
                        "title": "Quant Hub Acceptance",
                        "version": "1",
                    }
                },
            }
        )
        initialized = wait_response(0).get("result")
        if (
            not isinstance(initialized, dict)
            or initialized.get("platformFamily") != "windows"
            or initialized.get("platformOs") != "windows"
        ):
            raise ValueError("Codex config observer initialized on another platform")
        send(
            {
                "method": "config/read",
                "id": 1,
                "params": {
                    "includeLayers": True,
                    "cwd": str(config["working_directory"]),
                },
            }
        )
        result = wait_response(1).get("result")
        if not isinstance(result, dict):
            raise ValueError("Codex config observer returned no layer stack")
        summaries = _summarize_codex_non_user_layers(result.get("layers"))
        if process.stdin is not None:
            process.stdin.close()
        exit_code = process.wait(timeout=20)
        for thread in threads:
            thread.join(timeout=5)
        if (
            exit_code != 0
            or any(thread.is_alive() for thread in threads)
            or state["overflow"]
            or state["error"]
        ):
            raise ValueError("Codex config observer did not close cleanly")
        return {"non_user_layers": summaries}
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Codex effective config observation failed") from error
    finally:
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass


def _openai_subject(value: str) -> bool:
    return bool(
        re.search(r"(?:^|,)\s*(?:CN|O)\s*=\s*\"?OpenAI\b", value, re.IGNORECASE)
    )


def collect_openai_authenticode(path: Path) -> dict[str, str]:
    """Collect a trusted Windows Authenticode identity for the Codex binary."""

    if os.name != "nt":
        raise ValueError("real-Codex process provenance requires Windows")
    executable = assert_canonical_no_reparse_path(path, kind="Codex executable")
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        r"System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    script = (
        "$ErrorActionPreference='Stop';"
        "$s=Get-AuthenticodeSignature -LiteralPath $env:QRH_CODEX_SIGNATURE_PATH;"
        "[pscustomobject]@{status=[string]$s.Status;"
        "signer_subject=[string]$s.SignerCertificate.Subject;"
        "signer_thumbprint=[string]$s.SignerCertificate.Thumbprint}"
        "|ConvertTo-Json -Compress"
    )
    try:
        environment = dict(os.environ)
        environment["QRH_CODEX_SIGNATURE_PATH"] = str(executable)
        result = subprocess.run(
            [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Codex Authenticode observation failed") from error
    if result.returncode != 0 or len(result.stdout) > 64 * 1024:
        raise ValueError("Codex Authenticode observation failed")
    try:
        value = json.loads(
            result.stdout.decode("utf-8-sig", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("Codex Authenticode observation is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"status", "signer_subject", "signer_thumbprint"}
        or value.get("status") != "Valid"
        or not isinstance(value.get("signer_subject"), str)
        or not _openai_subject(value["signer_subject"])
        or not _is_thumbprint(value.get("signer_thumbprint"))
    ):
        raise ValueError("Codex executable lacks a valid OpenAI Authenticode signature")
    return {
        "status": "Valid",
        "signer_subject": value["signer_subject"],
        "signer_thumbprint": value["signer_thumbprint"].upper(),
    }


def observe_static_provenance(config: Mapping[str, object]) -> dict[str, object]:
    server = config["mcp_server"]
    if not isinstance(server, Mapping):
        raise ValueError("MCP server provenance is invalid")
    codex_executable = _stable_file_observation(
        Path(str(config["codex_executable"])), kind="Codex executable"
    )
    observation = {
        "codex_executable": codex_executable,
        "codex_authenticode": collect_openai_authenticode(
            Path(str(config["codex_executable"]))
        ),
        "mcp_command": _stable_file_observation(
            Path(str(server["command"])), kind="MCP command"
        ),
        "mcp_client_config": _stable_file_observation(
            Path(str(server["client_config_path"])), kind="MCP client config"
        ),
        "mcp_python_executable": _stable_file_observation(
            Path(str(server["python_executable"])), kind="MCP Python executable"
        ),
        "mcp_runtime_closures": [
            _observe_runtime_closure(closure)
            for closure in server["runtime_closures"]
        ],
        "codex_working_directory": _directory_observation(
            Path(str(config["working_directory"])), kind="Codex working directory"
        ),
        "mcp_working_directory": _directory_observation(
            Path(str(server["cwd"])), kind="MCP working directory"
        ),
        "codex_non_user_config_layers": _observe_codex_non_user_layers(
            config, codex_executable
        ),
    }
    if (
        observation["codex_executable"]["sha256"] != config["codex_executable_sha256"]
        or observation["codex_authenticode"] != config["codex_authenticode"]
        or observation["mcp_command"]["sha256"] != server["command_sha256"]
        or observation["mcp_client_config"]["sha256"] != server["client_config_sha256"]
        or observation["mcp_python_executable"]["sha256"]
        != server["python_executable_sha256"]
    ):
        raise ValueError("real acceptance provenance differs from launch config")
    return observation


def _observe_runtime_closure(value: Mapping[str, object]) -> dict[str, object]:
    root = assert_canonical_no_reparse_path(
        Path(str(value["root"])), kind=f"MCP runtime closure {value['name']}"
    )
    if not root.is_dir():
        raise ValueError("MCP runtime closure root must be a directory")
    actual: list[dict[str, object]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        before = sorted(entry.name for entry in os.scandir(directory))
        for name in before:
            child = directory / name
            relative = child.relative_to(root).as_posix()
            resolved = assert_canonical_no_reparse_path(
                child, kind=f"MCP runtime file {relative}"
            )
            if resolved.is_dir():
                pending.append(resolved)
            else:
                observation = _stable_file_observation(
                    resolved, kind=f"MCP runtime file {relative}"
                )
                actual.append(
                    {
                        "relative_path": relative,
                        "sha256": observation["sha256"],
                        "bytes": observation["bytes"],
                        "file_identity": observation["file_identity"],
                        "mtime_ns": observation["mtime_ns"],
                    }
                )
        if before != sorted(entry.name for entry in os.scandir(directory)):
            raise ValueError("MCP runtime closure changed while observed")
    actual.sort(key=lambda item: str(item["relative_path"]))
    expected = [
        {"relative_path": row["relative_path"], "sha256": row["sha256"]}
        for row in value["files"]
    ]
    projected = [
        {"relative_path": row["relative_path"], "sha256": row["sha256"]}
        for row in actual
    ]
    if projected != expected:
        raise ValueError("MCP runtime closure inventory differs from launch config")
    return {
        "name": value["name"],
        "root": str(root),
        "files": actual,
        "inventory_sha256": hashlib.sha256(
            canonical_json(projected).encode("utf-8")
        ).hexdigest(),
    }


class WindowsRuntimePins:
    """No-share-write/delete handles held for one complete acceptance arm."""

    def __init__(self, handles: list[int]) -> None:
        self._handles = handles

    def close(self) -> None:
        if os.name != "nt":
            raise ValueError("Windows runtime pin close is unavailable")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        failed = False
        while self._handles:
            handle = self._handles.pop()
            if not close_handle(handle):
                failed = True
        if failed:
            raise ValueError("Windows runtime pin close failed")

    def __del__(self) -> None:
        if self._handles:
            try:
                self.close()
            except BaseException:
                pass


def pin_runtime_closure(config: Mapping[str, object]) -> WindowsRuntimePins:
    """Pin every executable/config/package byte through the whole arm."""

    if os.name != "nt":
        raise ValueError("real-Codex runtime pinning requires Windows")
    server = config["mcp_server"]
    paths = {
        Path(str(config["codex_executable"])),
        Path(str(server["command"])),
        Path(str(server["python_executable"])),
        Path(str(server["client_config_path"])),
    }
    for closure in server["runtime_closures"]:
        root = Path(str(closure["root"]))
        paths.update(root / str(row["relative_path"]) for row in closure["files"])
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    handles: list[int] = []
    invalid = ctypes.c_void_p(-1).value
    try:
        for path in sorted(paths, key=lambda item: _normal_path(item)):
            resolved = assert_canonical_no_reparse_path(path, kind="runtime pin target")
            handle = create_file(
                str(resolved), 0x80000000, 0x00000001, None, 3,
                0x02000000, None,
            )  # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, BACKUP_SEMANTICS
            if not handle or int(handle) == invalid:
                raise ValueError("runtime pin target cannot be held no-share-delete")
            handles.append(int(handle))
    except BaseException:
        while handles:
            close_handle(handles.pop())
        raise
    return WindowsRuntimePins(handles)


def observe_windows_process_image(pid: int) -> dict[str, object]:
    """Query the live Windows process image and bind it to stable file bytes."""

    if os.name != "nt" or type(pid) is not int or pid <= 0:
        raise ValueError("live Windows process identity is unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    query_image.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    handle = open_process(0x1000, False, pid)
    if not handle:
        raise ValueError("live Windows process cannot be opened")
    try:
        capacity = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(capacity.value)
        if not query_image(handle, 0, buffer, ctypes.byref(capacity)):
            raise ValueError("live Windows process image cannot be queried")
        image = _stable_file_observation(Path(buffer.value), kind="live Codex process image")
    finally:
        close_handle(handle)
    return {"pid": pid, "image": image}


def observe_windows_descendant_image(
    root_pid: int, expected_image: Path
) -> dict[str, object] | None:
    """Observe a live descendant whose kernel image is the frozen MCP launcher."""

    if os.name != "nt" or type(root_pid) is not int or root_pid <= 0:
        raise ValueError("Codex root process identity is invalid")

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot_fn = kernel32.CreateToolhelp32Snapshot
    snapshot_fn.argtypes = (wintypes.DWORD, wintypes.DWORD)
    snapshot_fn.restype = wintypes.HANDLE
    first = kernel32.Process32FirstW
    first.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    first.restype = wintypes.BOOL
    next_entry = kernel32.Process32NextW
    next_entry.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    next_entry.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    snapshot = snapshot_fn(0x00000002, 0)  # TH32CS_SNAPPROCESS
    invalid = ctypes.c_void_p(-1).value
    if not snapshot or int(snapshot) == invalid:
        raise ValueError("Windows process snapshot failed")
    parents: dict[int, int] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if first(snapshot, ctypes.byref(entry)):
            while True:
                parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                entry.dwSize = ctypes.sizeof(entry)
                if not next_entry(snapshot, ctypes.byref(entry)):
                    break
    finally:
        close_handle(snapshot)
    descendants: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if pid not in descendants and (parent == root_pid or parent in descendants):
                descendants.add(pid)
                changed = True
    expected = _normal_path(expected_image)
    for pid in sorted(descendants):
        try:
            observation = observe_windows_process_image(pid)
        except ValueError:
            continue
        if _normal_path(str(observation["image"]["path"])) == expected:
            return observation
    return None


def validate_process_observation(
    config: Mapping[str, object],
    process: Mapping[str, object],
    static: Mapping[str, object],
) -> None:
    if (
        not isinstance(process, Mapping)
        or set(process) != {"pid", "image"}
        or type(process.get("pid")) is not int
        or process["pid"] <= 0
        or not isinstance(process.get("image"), Mapping)
        or process["image"] != static.get("codex_executable")
        or _normal_path(str(process["image"].get("path", "")))
        != _normal_path(str(config["codex_executable"]))
    ):
        raise ValueError("live Codex process image differs from frozen executable")


def validate_mcp_process_observation(
    config: Mapping[str, object],
    process: Mapping[str, object],
    static: Mapping[str, object],
    *,
    arm: str,
) -> None:
    if not isinstance(process, Mapping) or set(process) != {"launcher", "python"}:
        raise ValueError("MCP process observation is not closed")
    launcher = process.get("launcher")
    python = process.get("python")
    if arm == "no_mcp":
        if launcher is not None or python is not None:
            raise ValueError("no-MCP arm launched the frozen target MCP runtime")
        return
    if (
        arm != "assisted"
        or not isinstance(launcher, Mapping)
        or set(launcher) != {"pid", "image"}
        or type(launcher.get("pid")) is not int
        or launcher["pid"] <= 0
        or launcher.get("image") != static.get("mcp_command")
        or _normal_path(str(launcher["image"].get("path", "")))
        != _normal_path(str(config["mcp_server"]["command"]))
        or not isinstance(python, Mapping)
        or set(python) != {"pid", "image"}
        or type(python.get("pid")) is not int
        or python["pid"] <= 0
        or python.get("image") != static.get("mcp_python_executable")
        or _normal_path(str(python["image"].get("path", "")))
        != _normal_path(str(config["mcp_server"]["python_executable"]))
    ):
        raise ValueError("assisted arm lacks the frozen live target MCP runtime")


def validate_evidence_root(
    config: Mapping[str, object], evidence_root: Path, *, must_be_new: bool
) -> Path:
    parent = assert_canonical_no_reparse_path(
        Path(str(config["evidence_parent"])), kind="acceptance evidence parent"
    )
    if not parent.is_dir():
        raise ValueError("acceptance evidence parent is not a directory")
    root = Path(evidence_root)
    if not root.is_absolute():
        root = Path.cwd() / root
    if _normal_path(root.parent) != _normal_path(parent):
        raise ValueError("acceptance evidence root must be a direct child of evidence_parent")
    candidate = assert_canonical_no_reparse_path(
        root, kind="acceptance evidence root", allow_missing_leaf=must_be_new
    )
    if must_be_new and candidate.exists():
        raise FileExistsError(candidate)
    if config["execution_scope"] == "production_exact_d":
        if os.name != "nt":
            raise ValueError("production_exact_d acceptance requires Windows")
        audit_root = assert_canonical_no_reparse_path(
            PRODUCTION_AUDIT_ROOT, kind="production audit root"
        )
        if not parent.is_relative_to(audit_root):
            raise ValueError("production evidence_parent must stay below exact-D audit root")
    return candidate


def _validate_string_list(
    value: object, *, label: str, maximum: int = 128, allow_empty: bool = True
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or len(value) > maximum
        or any(
            not isinstance(item, str) or not item
            or len(item.encode("utf-8")) > 4096
            or any(character in item for character in ("\x00", "\r", "\n"))
            for item in value
        )
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"{label} is invalid")
    return tuple(value)


def _validate_server(value: object) -> Mapping[str, object]:
    fields = {
        "command", "command_sha256", "args", "cwd", "env", "env_vars",
        "enabled", "required", "enabled_tools", "default_tools_approval_mode",
        "startup_timeout_sec", "tool_timeout_sec", "client_config_path",
        "client_config_sha256", "python_executable", "python_executable_sha256",
        "runtime_closures",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("real MCP server config fields are not closed")
    command = value["command"]
    cwd = value["cwd"]
    client_path = value["client_config_path"]
    python_executable = value["python_executable"]
    args = _validate_string_list(value["args"], label="MCP args")
    env_vars = _validate_string_list(value["env_vars"], label="MCP env_vars")
    enabled_tools = _validate_string_list(
        value["enabled_tools"], label="MCP enabled_tools", allow_empty=False
    )
    env = value["env"]
    closures_value = value.get("runtime_closures")
    first_closure = (
        closures_value[0]
        if isinstance(closures_value, list) and closures_value
        else None
    )
    package_root_value = (
        first_closure.get("root") if isinstance(first_closure, dict) else None
    )
    expected_env = (
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": str(Path(package_root_value).parent),
            "PYTHONSAFEPATH": "1",
            "PYTHONUTF8": "1",
        }
        if isinstance(package_root_value, str) and package_root_value
        else None
    )
    if (
        not isinstance(command, str) or not command or not Path(command).is_absolute()
        or not _is_sha256(value["command_sha256"])
        or not isinstance(cwd, str) or not cwd or not Path(cwd).is_absolute()
        or not isinstance(client_path, str) or not client_path
        or not Path(client_path).is_absolute()
        or not _is_sha256(value["client_config_sha256"])
        or not isinstance(python_executable, str) or not python_executable
        or not Path(python_executable).is_absolute()
        or not _is_sha256(value["python_executable_sha256"])
        or value["enabled"] is not True or value["required"] is not True
        or value["default_tools_approval_mode"] != "writes"
        or type(value["startup_timeout_sec"]) is not int
        or not 1 <= value["startup_timeout_sec"] <= 300
        or type(value["tool_timeout_sec"]) is not int
        or not 1 <= value["tool_timeout_sec"] <= 3600
        or env != expected_env
        or env_vars
        or args != ("serve-stdio", "--client-config", client_path)
        or enabled_tools
        != (
            "search_quant_knowledge",
            "get_quant_knowledge",
            "list_knowledge_updates",
        )
    ):
        raise ValueError("real MCP server config values are invalid")
    if _normal_path(args[2]) != _normal_path(client_path):
        raise ValueError("MCP args do not bind the frozen client config")
    if os.name == "nt" and Path(command).suffix.casefold() in _WINDOWS_SCRIPT_SUFFIXES:
        raise ValueError("Windows MCP command must be a native executable")
    if os.name == "nt" and (
        Path(command).suffix.casefold() != ".exe"
        or Path(python_executable).suffix.casefold() != ".exe"
        or Path(command).name.casefold() != "qrh-knowledge-mcp.exe"
        or _normal_path(command) == _normal_path(python_executable)
    ):
        raise ValueError("Windows MCP launcher and Python must be native .exe files")
    closures = value["runtime_closures"]
    if not isinstance(closures, list) or [row.get("name") if isinstance(row, dict) else None for row in closures] != [
        "quant_hub_package", "quant_hub_distribution"
    ]:
        raise ValueError("MCP runtime closures must bind package and distribution")
    for closure in closures:
        if (
            not isinstance(closure, dict)
            or set(closure) != {"name", "root", "files"}
            or not isinstance(closure["root"], str)
            or not Path(closure["root"]).is_absolute()
            or not isinstance(closure["files"], list)
            or not closure["files"]
        ):
            raise ValueError("MCP runtime closure is invalid")
        prior = ""
        for row in closure["files"]:
            if (
                not isinstance(row, dict)
                or set(row) != {"relative_path", "sha256"}
                or not isinstance(row["relative_path"], str)
                or not row["relative_path"]
                or Path(row["relative_path"]).is_absolute()
                or ".." in Path(row["relative_path"]).parts
                or row["relative_path"].replace("\\", "/") != row["relative_path"]
                or row["relative_path"] <= prior
                or not _is_sha256(row["sha256"])
            ):
                raise ValueError("MCP runtime closure file inventory is invalid")
            prior = row["relative_path"]
    return value


def validate_real_codex_launch_config_bytes(
    payload: bytes, *, server_name: str
) -> Mapping[str, object]:
    """Validate the exact non-secret command and provenance policy."""

    if not isinstance(payload, bytes) or not payload or len(payload) > 1024 * 1024:
        raise ValueError("real Codex launch config bytes are invalid")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("real Codex launch config is invalid JSON") from error
    fields = {
        "schema_version", "execution_scope", "evidence_parent",
        "codex_executable", "codex_executable_sha256", "codex_authenticode",
        "working_directory", "sandbox", "timeout_seconds", "skip_git_repo_check",
        "mcp_server",
    }
    if (
        not isinstance(value, dict) or set(value) != fields
        or value.get("schema_version") != REAL_CODEX_LAUNCH_SCHEMA
        or canonical_json(value).encode("utf-8") != payload
    ):
        raise ValueError("real Codex launch config is not closed canonical JSON")
    executable = value["codex_executable"]
    signature = value["codex_authenticode"]
    working_directory = value["working_directory"]
    timeout_seconds = value["timeout_seconds"]
    if (
        not isinstance(server_name, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", server_name)
        or value["execution_scope"] not in {"local", "production_exact_d"}
        or not isinstance(value["evidence_parent"], str)
        or not Path(value["evidence_parent"]).is_absolute()
        or not isinstance(executable, str) or not executable
        or not Path(executable).is_absolute()
        or not _is_sha256(value["codex_executable_sha256"])
        or not isinstance(signature, dict)
        or set(signature) != {"status", "signer_subject", "signer_thumbprint"}
        or signature.get("status") != "Valid"
        or not isinstance(signature.get("signer_subject"), str)
        or not _openai_subject(signature["signer_subject"])
        or not _is_thumbprint(signature.get("signer_thumbprint"))
        or not isinstance(working_directory, str) or not working_directory
        or not Path(working_directory).is_absolute()
        or value["sandbox"] != "read-only"
        or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600
        or type(value["skip_git_repo_check"]) is not bool
    ):
        raise ValueError("real Codex launch config values are invalid")
    if os.name == "nt" and Path(executable).suffix.casefold() != ".exe":
        raise ValueError("Windows Codex executable must be a native .exe")
    _validate_server(value["mcp_server"])
    return value


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_list(values: Sequence[str]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _toml_inline_table(values: Mapping[str, str]) -> str:
    return "{" + ", ".join(
        f"{key} = {_toml_string(values[key])}" for key in sorted(values)
    ) + "}"


def _server_overrides(
    server_name: str, server: Mapping[str, object], *, enabled: bool
) -> tuple[str, ...]:
    fields = (
        "command=" + _toml_string(str(server["command"])),
        "args=" + _toml_list(tuple(str(item) for item in server["args"])),
        "cwd=" + _toml_string(str(server["cwd"])),
        "env=" + _toml_inline_table(server["env"]),
        "env_vars=" + _toml_list(tuple(str(item) for item in server["env_vars"])),
        "required=true",
        "enabled_tools=" + _toml_list(tuple(str(item) for item in server["enabled_tools"])),
        "default_tools_approval_mode="
        + _toml_string(str(server["default_tools_approval_mode"])),
        "startup_timeout_sec=" + str(server["startup_timeout_sec"]),
        "tool_timeout_sec=" + str(server["tool_timeout_sec"]),
        "enabled=" + str(enabled).lower(),
    )
    return (f"mcp_servers={{{server_name}={{" + ",".join(fields) + "}}",)


def _codex_isolation_overrides() -> tuple[str, ...]:
    return (
        "features.apps=false",
        "features.enable_mcp_apps=false",
        "features.plugins=false",
        "features.tool_search=false",
    )


def build_real_codex_command(
    config: Mapping[str, object], *, server_name: str, model: str, arm: str
) -> tuple[str, ...]:
    """Build closed assisted/control commands differing only in target enabled."""

    if arm not in {"assisted", "no_mcp"} or not isinstance(model, str) or not model:
        raise ValueError("real Codex command identity is invalid")
    server = config["mcp_server"]
    if not isinstance(server, Mapping):
        raise ValueError("real Codex MCP server config is invalid")
    command = [
        str(config["codex_executable"]), "exec", "--json", "--ephemeral",
        "--color", "never", "--ignore-user-config", "--ignore-rules",
        "--strict-config", "--model", model, "--sandbox", "read-only",
        "--cd", str(config["working_directory"]),
    ]
    if config["skip_git_repo_check"] is True:
        command.append("--skip-git-repo-check")
    for override in _server_overrides(server_name, server, enabled=arm == "assisted"):
        command.extend(("--config", override))
    for override in _codex_isolation_overrides():
        command.extend(("--config", override))
    command.append("-")
    return tuple(command)


def validate_arm_command_difference(
    config: Mapping[str, object], *, server_name: str, model: str
) -> None:
    assisted = build_real_codex_command(
        config, server_name=server_name, model=model, arm="assisted"
    )
    control = build_real_codex_command(
        config, server_name=server_name, model=model, arm="no_mcp"
    )
    differences = [(left, right) for left, right in zip(assisted, control) if left != right]
    if (
        len(assisted) != len(control)
        or len(differences) != 1
        or differences[0][0].replace("enabled=true", "enabled=false")
        != differences[0][1]
        or differences[0][0].count("enabled=true") != 1
    ):
        raise ValueError("assisted and no-MCP commands differ beyond target enabled")


def real_case_key(*, run_id: str, case_id: str) -> str:
    material = canonical_json({"run_id": run_id, "case_id": case_id})
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def real_prompt_path(root: Path, *, run_id: str, case_id: str) -> Path:
    return Path(root) / "cases" / f"{real_case_key(run_id=run_id, case_id=case_id)}.prompt.bin"


def real_dispatch_paths(
    root: Path, *, run_id: str, case_id: str, arm: str
) -> tuple[Path, Path, Path]:
    if arm not in {"assisted", "no_mcp"}:
        raise ValueError("real Codex acceptance arm is invalid")
    material = canonical_json({"run_id": run_id, "case_id": case_id, "arm": arm})
    key = hashlib.sha256(material.encode("utf-8")).hexdigest()
    base = Path(root)
    return (
        base / f"{key}.intent.json",
        base / f"{key}.trace.jsonl",
        base / f"{key}.complete.json",
    )


def build_real_request_material(
    *, run_id: str, case_id: str, arm: str,
    authority_identity: Mapping[str, object], server_name: str, model: str,
    prompt_bytes: bytes, config_bytes: bytes, command: Sequence[str],
) -> dict[str, object]:
    return {
        "run_id": run_id, "case_id": case_id, "arm": arm,
        "authority_identity": dict(authority_identity), "server_name": server_name,
        "model": model, "prompt_bytes": len(prompt_bytes),
        "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
        "config_bytes": len(config_bytes),
        "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "command": list(command),
    }


__all__ = [
    "NON_QUALIFYING_CODEX_RUNNER", "PRODUCTION_AUDIT_ROOT",
    "PUBLIC_SYNTHETIC_ACCEPTANCE_AUTHORITY",
    "REAL_ACCEPTANCE_INPUT_SCHEMA", "REAL_ACCEPTANCE_PROMPTS_SCHEMA",
    "REAL_CODEX_EVIDENCE_REPLAY_AUTHORITY",
    "REAL_CODEX_LAUNCH_SCHEMA", "REAL_CODEX_RUNNER",
    "assert_canonical_no_reparse_path", "build_real_codex_command",
    "build_real_request_material", "collect_openai_authenticode",
    "observe_static_provenance", "observe_windows_process_image",
    "observe_windows_descendant_image",
    "pin_runtime_closure",
    "real_case_key", "real_dispatch_paths", "real_prompt_path", "stable_read_file",
    "validate_arm_command_difference", "validate_evidence_root",
    "validate_mcp_process_observation",
    "validate_process_observation", "validate_real_codex_launch_config_bytes",
]
