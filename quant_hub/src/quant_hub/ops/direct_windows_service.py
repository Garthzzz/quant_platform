"""Minimal SCM host for the explicitly requested direct production start."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import win32event
import win32service
import win32serviceutil


ROOT = Path(r"D:\quant\quant_platform")
RELEASE_ID = "release-2157a1209d85-227b30ef6fbb"
MANIFEST_SHA256 = "e2e6563d7f73b5e3ad1dd4478cc83493c40dbc96db67b928cfc6224df1577000"


class QuantResearchHubDirectWindowsService(win32serviceutil.ServiceFramework):
    _svc_name_ = "QuantResearchHub"
    _svc_display_name_ = "Quant Research Hub"
    _svc_description_ = "D-root direct Quant Research Hub service"

    def __init__(self, args):
        super().__init__(args)
        self._stop_event = win32event.CreateEvent(None, True, False, None)
        self._process: subprocess.Popen[bytes] | None = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()

    def SvcDoRun(self):
        python = ROOT / "tooling" / "python" / "python.exe"
        service_temp = ROOT / "tmp" / "service"
        service_temp.mkdir(parents=True, exist_ok=True)
        environment = dict(os.environ)
        environment.update(
            {
                "TEMP": str(service_temp),
                "TMP": str(service_temp),
                "PYTHONDONTWRITEBYTECODE": "1",
                "QRH_DIRECT_TRUST_SEALED_INVENTORY": "1",
                "QRH_DIRECT_PRESENTATION_ASSET_ROOT": str(
                    ROOT / "state" / "archive_presentation_assets"
                ),
            }
        )
        stdout_path = ROOT / "logs" / "direct-scm.stdout.log"
        stderr_path = ROOT / "logs" / "direct-scm.stderr.log"
        arguments = [
            str(python),
            "-B",
            "-m",
            "quant_hub.ops.service_entry",
            "--vm-root",
            str(ROOT),
            "--release-id",
            RELEASE_ID,
            "--manifest-sha256",
            MANIFEST_SHA256,
        ]
        with stdout_path.open("ab", buffering=0) as stdout, stderr_path.open(
            "ab", buffering=0
        ) as stderr:
            self._process = subprocess.Popen(
                arguments,
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            while True:
                wait = win32event.WaitForSingleObject(self._stop_event, 250)
                if wait == win32event.WAIT_OBJECT_0:
                    if self._process.poll() is None:
                        self._process.terminate()
                    self._process.wait(timeout=15)
                    return
                return_code = self._process.poll()
                if return_code is not None:
                    raise RuntimeError(
                        f"direct Quant Research Hub child exited with {return_code}"
                    )
