from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_PATH = PROJECT_ROOT / "tools" / "viewer" / "app.py"
CONFIG_PATH = LAUNCHER_PATH.with_name("reviewed_runtime.json")


def _load_launcher():
    spec = importlib.util.spec_from_file_location("quant_hub_local_viewer", LAUNCHER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_reviewed_runtime_resolves_configured_frozen_contract() -> None:
    launcher = _load_launcher()
    runtime = launcher.load_reviewed_runtime()
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    assert runtime.project_root == PROJECT_ROOT
    assert runtime.delivery_var == (PROJECT_ROOT / config["delivery_var"]).resolve()
    assert runtime.run_local.is_file()
    assert runtime.migration_root.is_dir()
    assert runtime.python_executable == Path(r"D:\conda\python.exe")
    assert runtime.python_version.startswith("3.13.")
    assert runtime.host == "localhost"
    assert runtime.port == 8765
    assert runtime.url == "http://localhost:8765/"


def test_command_uses_reviewed_python_not_active_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher = _load_launcher()
    runtime = launcher.load_reviewed_runtime()
    monkeypatch.setattr(launcher.sys, "executable", r"D:\conda\envs\quant\python.exe")

    command = launcher.build_command(runtime)

    assert command[0] == r"D:\conda\python.exe"
    assert command[0] != launcher.sys.executable
    assert command[1] == "-I"


def test_reviewed_runtime_rejects_tampered_gate(tmp_path: Path) -> None:
    launcher = _load_launcher()
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    config["startup_gate_sha256"] = "0" * 64
    bad_config = tmp_path / "reviewed_runtime.json"
    bad_config.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(launcher.LauncherError, match="审核资源已变化"):
        launcher.load_reviewed_runtime(bad_config)


def test_reviewed_python_rejects_replaced_executable(tmp_path: Path) -> None:
    launcher = _load_launcher()
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"reviewed-python")
    activation = tmp_path / "activation.json"
    activation.write_text(
        json.dumps(
            {
                "runtime_contract": {
                    "toolchain": {
                        "python_executable": str(executable),
                        "python_executable_identity": {
                            "bytes": executable.stat().st_size,
                            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                        },
                        "python_full_version": "3.13.12 | reviewed test runtime",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    assert launcher._reviewed_python(activation) == (
        executable.resolve(),
        "3.13.12 | reviewed test runtime",
    )

    executable.write_bytes(b"replaced-python")
    with pytest.raises(launcher.LauncherError, match="审核 Python 已被替换"):
        launcher._reviewed_python(activation)


def test_existing_hub_is_reused_without_spawning(monkeypatch: pytest.MonkeyPatch) -> None:
    launcher = _load_launcher()
    runtime = launcher.load_reviewed_runtime()
    monkeypatch.setattr(launcher, "_is_quant_hub", lambda _url: True)
    monkeypatch.setattr(
        launcher,
        "_port_is_open",
        lambda *_args: pytest.fail("识别到现有 Hub 后不应继续探测占用"),
    )

    assert launcher.launch(runtime, open_browser=False, timeout=1) == 0


def test_foreign_port_occupant_is_not_terminated_or_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    launcher = _load_launcher()
    runtime = launcher.load_reviewed_runtime()
    monkeypatch.setattr(launcher, "_is_quant_hub", lambda _url: False)
    monkeypatch.setattr(launcher, "_port_is_open", lambda *_args: True)
    monkeypatch.setattr(
        launcher.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("端口冲突时不应创建子进程"),
    )

    with pytest.raises(launcher.LauncherError, match="已被其他服务占用"):
        launcher.launch(runtime, open_browser=False, timeout=1)
