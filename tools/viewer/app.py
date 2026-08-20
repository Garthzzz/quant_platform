#!/usr/bin/env python3
"""Quant Research Hub 本地查看入口。

在项目根目录执行：

    python tools/viewer/app.py

若已审核的 Hub 已在运行，本脚本只打开浏览器；否则启动冻结交付、等待
服务就绪并打开浏览器。Ctrl+C 会关闭由本脚本启动的服务。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CONFIG_SCHEMA = "qrh-local-viewer-reviewed-runtime/v1"
HUB_MARKERS = ("Quant Research Hub", "量化研究知识中枢")


class LauncherError(RuntimeError):
    """可直接呈现给使用者的启动错误。"""


@dataclass(frozen=True)
class ReviewedRuntime:
    project_root: Path
    delivery_var: Path
    startup_gate: Path
    activation_seal: Path
    migration_root: Path
    run_local: Path
    python_executable: Path
    python_version: str
    host: str
    port: int

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise LauncherError(f"{label} 越出项目目录：{resolved}") from exc
    return resolved


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LauncherError(f"无法读取审核运行配置 {path}：{exc}") from exc
    if not isinstance(value, dict):
        raise LauncherError(f"审核运行配置必须是 JSON 对象：{path}")
    return value


def _reviewed_python(activation_seal: Path) -> tuple[Path, str]:
    activation = _load_object(activation_seal)
    runtime_contract = activation.get("runtime_contract")
    toolchain = (
        runtime_contract.get("toolchain")
        if isinstance(runtime_contract, dict)
        else None
    )
    if not isinstance(toolchain, dict):
        raise LauncherError("激活封印缺少审核 Python toolchain。")
    raw_executable = toolchain.get("python_executable")
    identity = toolchain.get("python_executable_identity")
    version = toolchain.get("python_full_version")
    if (
        not isinstance(raw_executable, str)
        or not raw_executable
        or not isinstance(identity, dict)
        or not isinstance(version, str)
        or not version
    ):
        raise LauncherError("激活封印中的审核 Python 契约不完整。")
    executable = Path(raw_executable).resolve(strict=False)
    if not executable.is_file():
        raise LauncherError(
            "找不到 V34 审核时使用的 Python："
            f"{executable}\n  要求版本：{version.split(' | ', 1)[0]}"
        )
    expected_bytes = identity.get("bytes")
    expected_sha256 = identity.get("sha256")
    if (
        not isinstance(expected_bytes, int)
        or isinstance(expected_bytes, bool)
        or not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
    ):
        raise LauncherError("激活封印中的审核 Python 文件身份无效。")
    actual_bytes = executable.stat().st_size
    actual_sha256 = _sha256(executable)
    if actual_bytes != expected_bytes or actual_sha256 != expected_sha256.lower():
        raise LauncherError(
            "审核 Python 已被替换，拒绝使用："
            f"{executable}\n"
            f"  文件大小：实际 {actual_bytes}，期望 {expected_bytes}\n"
            f"  SHA-256：实际 {actual_sha256}，期望 {expected_sha256.lower()}"
        )
    return executable, version


def load_reviewed_runtime(config_path: Path | None = None) -> ReviewedRuntime:
    script_path = Path(__file__).resolve()
    project_root = script_path.parents[2]
    config_path = (config_path or script_path.with_name("reviewed_runtime.json")).resolve()
    config = _load_object(config_path)

    if config.get("schema_version") != CONFIG_SCHEMA:
        raise LauncherError("reviewed_runtime.json 的 schema_version 不受支持。")
    host = config.get("host")
    port = config.get("port")
    if host != "localhost":
        raise LauncherError("本地查看入口只允许绑定 localhost。")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise LauncherError("reviewed_runtime.json 中的 port 无效。")
    if port == 8000:
        raise LauncherError("端口 8000 已明确保留给其他服务。")

    delivery_raw = config.get("delivery_var")
    gate_raw = config.get("startup_gate")
    if not isinstance(delivery_raw, str) or not isinstance(gate_raw, str):
        raise LauncherError("审核运行配置缺少 delivery_var 或 startup_gate。")

    delivery_var = _inside(project_root / delivery_raw, project_root / "quant_hub" / "var", "交付目录")
    startup_gate = _inside(project_root / gate_raw, project_root / "project_state" / "gates", "启动门禁")
    activation_seal = delivery_var / "ACTIVATED_DELIVERY_SEAL.json"
    migration_root = delivery_var / "runtime_contract" / "migrations" / "platform"
    run_local = delivery_var / "runtime_contract" / "code" / "tools" / "run_local.py"

    required = {
        "交付目录": delivery_var,
        "启动门禁": startup_gate,
        "激活封印": activation_seal,
        "数据库迁移目录": migration_root,
        "冻结启动脚本": run_local,
        "只读研究原文区": project_root / "reference" / "archive",
    }
    missing = [f"{label}：{path}" for label, path in required.items() if not path.exists()]
    if missing:
        raise LauncherError("审核运行资源不完整：\n  " + "\n  ".join(missing))

    expected_hashes = {
        activation_seal: config.get("activation_seal_sha256"),
        startup_gate: config.get("startup_gate_sha256"),
    }
    for path, expected in expected_hashes.items():
        if not isinstance(expected, str) or len(expected) != 64:
            raise LauncherError(f"缺少 {path.name} 的审核哈希。")
        actual = _sha256(path)
        if actual.lower() != expected.lower():
            raise LauncherError(
                f"审核资源已变化，拒绝启动：{path}\n"
                f"  期望 SHA-256：{expected.lower()}\n"
                f"  实际 SHA-256：{actual.lower()}"
            )

    python_executable, python_version = _reviewed_python(activation_seal)

    return ReviewedRuntime(
        project_root=project_root,
        delivery_var=delivery_var,
        startup_gate=startup_gate,
        activation_seal=activation_seal,
        migration_root=migration_root,
        run_local=run_local,
        python_executable=python_executable,
        python_version=python_version,
        host=host,
        port=port,
    )


def _port_is_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.8):
            return True
    except OSError:
        return False


def _is_quant_hub(url: str, timeout: float = 2.0) -> bool:
    request = urllib.request.Request(url, headers={"User-Agent": "QuantHubLocalViewer/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return False
            body = response.read(512 * 1024).decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        return False
    return all(marker in body for marker in HUB_MARKERS)


def build_command(runtime: ReviewedRuntime) -> list[str]:
    return [
        str(runtime.python_executable),
        "-I",
        str(runtime.run_local),
        "--project-root",
        str(runtime.project_root),
        "--archive-root",
        str(runtime.project_root / "reference" / "archive"),
        "--var-root",
        str(runtime.delivery_var),
        "--migration-root",
        str(runtime.migration_root),
        "--activation-seal",
        str(runtime.activation_seal),
        "--startup-gate",
        str(runtime.startup_gate),
        "--resume-reviewed-runtime",
        "--host",
        runtime.host,
        "--port",
        str(runtime.port),
    ]


def _open_browser(url: str, enabled: bool) -> None:
    if not enabled:
        return
    opened = webbrowser.open(url, new=2)
    if not opened:
        print(f"[Quant Hub] 浏览器未自动响应，请手动打开：{url}")


def _wait_until_ready(process: subprocess.Popen[bytes], runtime: ReviewedRuntime, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            raise LauncherError(f"Quant Research Hub 启动进程提前退出，退出码：{return_code}")
        if _is_quant_hub(runtime.url, timeout=0.8):
            return
        time.sleep(0.25)
    raise LauncherError(f"等待 Quant Research Hub 就绪超时（{timeout:g} 秒）：{runtime.url}")


def _stop_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def launch(runtime: ReviewedRuntime, *, open_browser: bool, timeout: float) -> int:
    if _is_quant_hub(runtime.url):
        print(f"[Quant Hub] 已在运行：{runtime.url}")
        _open_browser(runtime.url, open_browser)
        return 0
    if _port_is_open(runtime.host, runtime.port):
        raise LauncherError(
            f"{runtime.host}:{runtime.port} 已被其他服务占用；未终止该服务，也未重复启动 Quant Hub。"
        )

    current_python = Path(sys.executable).resolve()
    if current_python != runtime.python_executable:
        print(
            "[Quant Hub] 当前环境解释器不属于审核运行契约，自动切换：\n"
            f"  当前：{current_python}（Python {sys.version.split()[0]}）\n"
            f"  审核：{runtime.python_executable}"
            f"（Python {runtime.python_version.split(' | ', 1)[0]}）"
        )
    print(f"[Quant Hub] 正在启动已审核交付：{runtime.delivery_var.name}")
    process = subprocess.Popen(build_command(runtime), cwd=runtime.project_root)
    try:
        _wait_until_ready(process, runtime, timeout)
        print(f"[Quant Hub] 已就绪：{runtime.url}")
        _open_browser(runtime.url, open_browser)
        print("[Quant Hub] 保持此终端运行；按 Ctrl+C 关闭本次启动的服务。")
        return process.wait()
    except KeyboardInterrupt:
        print("\n[Quant Hub] 正在关闭本次启动的服务……")
        _stop_child(process)
        return 0
    except BaseException:
        _stop_child(process)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="启动并打开已审核的 Quant Research Hub 本地网页。")
    parser.add_argument("--no-browser", action="store_true", help="启动服务但不自动打开浏览器。")
    parser.add_argument("--check", action="store_true", help="只校验审核运行配置并检查服务状态。")
    parser.add_argument("--print-command", action="store_true", help="打印底层冻结启动命令后退出。")
    parser.add_argument("--wait-timeout", type=float, default=90.0, help="等待服务就绪的秒数（默认 90）。")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.wait_timeout <= 0:
            raise LauncherError("--wait-timeout 必须大于 0。")
        runtime = load_reviewed_runtime()
        if args.print_command:
            print(subprocess.list2cmdline(build_command(runtime)))
            return 0
        if args.check:
            state = "正在运行" if _is_quant_hub(runtime.url) else "尚未运行"
            print(f"[Quant Hub] 审核运行配置有效；服务{state}：{runtime.url}")
            return 0
        return launch(runtime, open_browser=not args.no_browser, timeout=args.wait_timeout)
    except LauncherError as exc:
        print(f"[Quant Hub] 启动失败：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
