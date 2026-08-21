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
PROBE_SCHEMA = "qrh-recovery-independence-probe/v2"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


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
    required = {
        "schema_version",
        "production_root_available",
        "recovery_bundle_readable",
        "closure_verified",
        "empty_root_precondition",
        "bundle_id",
        "release_id",
        "release_manifest_sha256",
        "bundle_inventory_sha256",
        "materialization_event_id",
        "materialization_event_sha256",
        "probe_tool_sha256",
    }
    if set(probe) != required:
        raise FailureDomainError("independence probe shape is invalid")
    if probe.get("schema_version") != PROBE_SCHEMA:
        raise FailureDomainError("independence probe schema is invalid")
    if probe.get("production_root_available") is not False:
        raise FailureDomainError("probe did not isolate the production root")
    if (
        probe.get("recovery_bundle_readable") is not True
        or probe.get("closure_verified") is not True
        or probe.get("empty_root_precondition") is not True
    ):
        raise FailureDomainError("recovery bundle was not independently verified")
    for field in (
        "release_manifest_sha256",
        "bundle_inventory_sha256",
        "materialization_event_sha256",
        "probe_tool_sha256",
    ):
        if not isinstance(probe.get(field), str) or not _SHA256_RE.fullmatch(str(probe[field])):
            raise FailureDomainError(f"independence probe {field} is invalid")
    for field in ("bundle_id", "release_id", "materialization_event_id"):
        if not isinstance(probe.get(field), str) or not _SAFE_ID_RE.fullmatch(str(probe[field])):
            raise FailureDomainError(f"independence probe {field} is invalid")
    if probe["materialization_event_id"] != "cold-materialization-" + str(
        probe["bundle_id"]
    ):
        raise FailureDomainError("independence probe materialization event differs")
    return probe


def build_independence_probe(
    *,
    recovery_root: Path,
    bundle_root: Path,
    materialization_event_path: Path,
    probe_tool_path: Path,
) -> dict[str, object]:
    """Bind an off-host bundle to a real empty-D materialization event.

    This is the mechanical proof behind ``production_root_available=false``:
    the sole production VM reported an exact empty D root before materializing
    the bundle, while the same closed bundle remains readable and fully
    verifiable on the recovery host.  The event is evidence only and never an
    active/release authority.
    """

    from quant_hub.ops.recovery_bundle import verify_recovery_bundle

    recovery = Path(recovery_root).resolve(strict=True)
    bundle = Path(bundle_root).resolve(strict=True)
    event_path = Path(materialization_event_path).resolve(strict=True)
    tool_path = Path(probe_tool_path).resolve(strict=True)
    if not recovery.is_dir() or _path_has_reparse(recovery):
        raise FailureDomainError("recovery root is not a stable local directory")
    if bundle.parent != recovery or not bundle.is_dir() or _path_has_reparse(bundle):
        raise FailureDomainError("recovery bundle is outside the attested root")
    for path, label in ((event_path, "materialization event"), (tool_path, "probe tool")):
        if not path.is_file() or _path_has_reparse(path):
            raise FailureDomainError(f"{label} is not a regular independent file")
    report = verify_recovery_bundle(bundle)
    if (
        not report.valid
        or report.bundle_id is None
        or report.release_id is None
        or report.release_manifest_sha256 is None
    ):
        raise FailureDomainError("off-host recovery bundle verification failed")
    try:
        event_raw = event_path.read_bytes()
        event = json.loads(event_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FailureDomainError("materialization event is unreadable") from error
    if not isinstance(event, dict) or set(event) != {
        "schema_version", "event_id", "kind", "authority", "fields"
    }:
        raise FailureDomainError("materialization event shape is invalid")
    fields = event.get("fields")
    if not isinstance(fields, dict) or set(fields) != {
        "bundle_id",
        "release_id",
        "manifest_sha256",
        "empty_root_precondition",
        "import_cleaned",
        "runtime_tmp_cleaned",
    }:
        raise FailureDomainError("materialization event fields are invalid")
    expected_event_id = "cold-materialization-" + report.bundle_id
    if (
        event.get("schema_version") != "qrh-recovery-materialization-event/v1"
        or event.get("event_id") != expected_event_id
        or event.get("kind") != "cold_recovery_materialized"
        or event.get("authority") != "evidence_only"
        or fields.get("bundle_id") != report.bundle_id
        or fields.get("release_id") != report.release_id
        or fields.get("manifest_sha256") != report.release_manifest_sha256
        or any(
            fields.get(name) is not True
            for name in (
                "empty_root_precondition", "import_cleaned", "runtime_tmp_cleaned"
            )
        )
    ):
        raise FailureDomainError("materialization event does not bind the bundle")
    inventory = bundle / "closure_inventory.json"
    probe = {
        "schema_version": PROBE_SCHEMA,
        "production_root_available": False,
        "recovery_bundle_readable": True,
        "closure_verified": True,
        "empty_root_precondition": True,
        "bundle_id": report.bundle_id,
        "release_id": report.release_id,
        "release_manifest_sha256": report.release_manifest_sha256,
        "bundle_inventory_sha256": hashlib.sha256(inventory.read_bytes()).hexdigest(),
        "materialization_event_id": expected_event_id,
        "materialization_event_sha256": hashlib.sha256(event_raw).hexdigest(),
        "probe_tool_sha256": hashlib.sha256(tool_path.read_bytes()).hexdigest(),
    }
    return verify_independence_probe(probe)


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
    "build_independence_probe",
    "canonical_bytes",
    "collect_host_facts",
    "verify_host_facts",
    "verify_independence_probe",
]
