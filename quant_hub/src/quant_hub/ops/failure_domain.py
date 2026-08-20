"""Machine-verifiable recovery failure-domain facts and attestation.

The production and recovery probes run on their respective hosts.  The
attestation accepts only a different host identity and storage authority, a
non-reparse recovery root, and an independence probe that can verify retained
bytes without consulting the production root.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
from typing import Mapping


FACTS_SCHEMA = "qrh-failure-domain-host-facts/v1"
ATTESTATION_SCHEMA = "qrh-recovery-failure-domain-attestation/v1"
PROBE_SCHEMA = "qrh-recovery-independence-probe/v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class FailureDomainError(RuntimeError):
    """The candidate recovery root is not independently recoverable."""


@dataclass(frozen=True)
class FailureDomainAttestation:
    payload: dict[str, object]
    sha256: str


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _machine_identity() -> str:
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            ) as key:
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
            if isinstance(value, str) and value.strip():
                return "windows-machine-guid:" + value.strip().casefold()
        except OSError:
            pass
    node = platform.node().strip().casefold()
    if not node:
        raise FailureDomainError("host has no stable machine identity")
    return "host-name:" + node


def _is_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(os.stat_result, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _path_has_reparse(path: Path) -> bool:
    current = path
    while True:
        if current.exists() and _is_reparse(current):
            return True
        if current.parent == current:
            return False
        current = current.parent


def _windows_volume(path: Path) -> tuple[str, str]:
    drive, _ = os.path.splitdrive(str(path))
    if os.name != "nt":
        device = str(path.stat().st_dev)
        return f"device:{device}", f"device:{device}"
    if not drive:
        raise FailureDomainError("Windows local path has no drive")
    import ctypes
    from ctypes import wintypes

    root = drive.upper() + "\\"
    volume_name = ctypes.create_unicode_buffer(261)
    filesystem_name = ctypes.create_unicode_buffer(261)
    serial = wintypes.DWORD()
    maximum_component = wintypes.DWORD()
    flags = wintypes.DWORD()
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        root,
        volume_name,
        len(volume_name),
        ctypes.byref(serial),
        ctypes.byref(maximum_component),
        ctypes.byref(flags),
        filesystem_name,
        len(filesystem_name),
    )
    if not ok:
        raise FailureDomainError(f"cannot resolve Windows volume for {root}")
    volume_id = f"windows-volume:{serial.value:08x}"
    backend = f"local-{filesystem_name.value.casefold()}:{root.casefold()}"
    return volume_id, backend


def collect_host_facts(root: Path, *, role: str, tool_version: str) -> dict[str, object]:
    if role not in {"production", "recovery"}:
        raise FailureDomainError("host role must be production or recovery")
    raw = Path(root)
    if not raw.exists() or not raw.is_dir():
        raise FailureDomainError(f"{role} root must be an existing directory")
    absolute = raw.absolute()
    resolved = raw.resolve(strict=True)
    raw_text = str(absolute)
    is_unc = raw_text.startswith(("\\\\", "//"))
    reparse = _path_has_reparse(absolute)
    volume_id, backend = _windows_volume(resolved)
    machine_id = _machine_identity()
    facts: dict[str, object] = {
        "schema_version": FACTS_SCHEMA,
        "role": role,
        "host_name": platform.node(),
        "machine_identity": machine_id,
        "canonical_path": str(resolved),
        "path_kind": "unc" if is_unc else "local",
        "reparse_or_symlink": reparse,
        "volume_identity": volume_id,
        "storage_backend": backend,
        "storage_authority": f"{machine_id}|{volume_id}|{backend}",
        "tool_version": tool_version,
    }
    facts["facts_sha256"] = hashlib.sha256(canonical_bytes(facts)).hexdigest()
    return facts


def verify_host_facts(value: Mapping[str, object], *, expected_role: str) -> dict[str, object]:
    facts = dict(value)
    claimed = facts.pop("facts_sha256", None)
    if facts.get("schema_version") != FACTS_SCHEMA or facts.get("role") != expected_role:
        raise FailureDomainError("host facts schema or role is invalid")
    required_text = (
        "host_name",
        "machine_identity",
        "canonical_path",
        "path_kind",
        "volume_identity",
        "storage_backend",
        "storage_authority",
        "tool_version",
    )
    if any(not isinstance(facts.get(field), str) or not facts[field] for field in required_text):
        raise FailureDomainError("host facts contain an empty identity field")
    if not isinstance(facts.get("reparse_or_symlink"), bool):
        raise FailureDomainError("host facts reparse flag is invalid")
    actual = hashlib.sha256(canonical_bytes(facts)).hexdigest()
    if claimed != actual:
        raise FailureDomainError("host facts hash differs")
    facts["facts_sha256"] = actual
    return facts


def verify_independence_probe(value: Mapping[str, object]) -> dict[str, object]:
    probe = dict(value)
    if probe.get("schema_version") != PROBE_SCHEMA:
        raise FailureDomainError("independence probe schema is invalid")
    if probe.get("production_root_available") is not False:
        raise FailureDomainError("probe did not isolate the production root")
    if probe.get("recovery_bundle_readable") is not True or probe.get("closure_verified") is not True:
        raise FailureDomainError("recovery bundle was not independently verified")
    for field in ("bundle_inventory_sha256", "probe_tool_sha256"):
        if not isinstance(probe.get(field), str) or not _SHA256_RE.fullmatch(str(probe[field])):
            raise FailureDomainError(f"independence probe {field} is invalid")
    return probe


def attest_failure_domain(
    *,
    production_facts: Mapping[str, object],
    recovery_facts: Mapping[str, object],
    independence_probe: Mapping[str, object],
    observed_at: str,
) -> FailureDomainAttestation:
    production = verify_host_facts(production_facts, expected_role="production")
    recovery = verify_host_facts(recovery_facts, expected_role="recovery")
    probe = verify_independence_probe(independence_probe)
    if production["machine_identity"] == recovery["machine_identity"]:
        raise FailureDomainError("recovery root is on the production host")
    if production["storage_authority"] == recovery["storage_authority"]:
        raise FailureDomainError("recovery root shares production storage authority")
    if recovery["reparse_or_symlink"] is not False:
        raise FailureDomainError("recovery root traverses a reparse/symlink boundary")
    if recovery["path_kind"] != "local":
        raise FailureDomainError("v1 recovery root must resolve to recovery-host local storage")
    if not isinstance(observed_at, str) or "T" not in observed_at:
        raise FailureDomainError("attestation observed_at is invalid")
    payload: dict[str, object] = {
        "schema_version": ATTESTATION_SCHEMA,
        "observed_at": observed_at,
        "production_host_facts_sha256": production["facts_sha256"],
        "recovery_host_facts_sha256": recovery["facts_sha256"],
        "production": production,
        "recovery": recovery,
        "independence_probe": probe,
        "verdict": "independent_failure_domain",
    }
    return FailureDomainAttestation(
        payload=payload,
        sha256=hashlib.sha256(canonical_bytes(payload)).hexdigest(),
    )


__all__ = [
    "ATTESTATION_SCHEMA",
    "FACTS_SCHEMA",
    "PROBE_SCHEMA",
    "FailureDomainAttestation",
    "FailureDomainError",
    "attest_failure_domain",
    "canonical_bytes",
    "collect_host_facts",
    "verify_host_facts",
    "verify_independence_probe",
]
