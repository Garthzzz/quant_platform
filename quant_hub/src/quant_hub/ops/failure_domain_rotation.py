"""Read-only diagnostics for the unfinished failure-domain rotation protocol.

The installed package intentionally contains no writer for rotation intents,
attestation history, ``current`` attestations, or completion receipts. A future
production implementation must use a separate module, a new schema, and a
non-serializable capability supplied by an SSH-host-authenticated runner.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
from typing import Mapping, Sequence
import unicodedata

from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point

from .failure_domain import (
    ATTESTATION_SCHEMA,
    FailureDomainError,
    attest_failure_domain,
    canonical_bytes,
    verify_host_facts,
    verify_independence_probe,
)
from .failure_domain_authority import (
    FailureDomainAuthorityNotReady,
    require_failure_domain_authority,
)


OBSERVATION_SCHEMA = "qrh-failure-domain-refresh-observation/v1"
INTENT_SCHEMA = "qrh-failure-domain-attestation-rotation-intent/v1"
COMPLETION_SCHEMA = "qrh-failure-domain-attestation-rotation-completion/v1"
CHALLENGE_SCHEMA = "qrh-failure-domain-refresh-challenge/v1"
CAPTURE_SCHEMA = "qrh-failure-domain-source-capture/v1"
SOURCE_MANIFEST_SCHEMA = "qrh-failure-domain-source-manifest/v1"
CAPTURE_TTL_SECONDS = 300
CAPTURE_MAX_SKEW_SECONDS = 30
MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 128
ROTATION_READINESS = "FAKE_ONLY/NOT_READY"
DIAGNOSTIC_READINESS = "SYNTHETIC/DIAGNOSTIC_ONLY"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SOURCE_PRODUCERS = {
    "production_facts": "qrh-production-host-facts",
    "recovery_facts": "qrh-failure-domain-recovery-facts",
    "independence_probe": "qrh-failure-domain-independence-probe",
}
_FORMAL_NOT_READY = (
    "FAKE_ONLY/NOT_READY: an exact Git/CI/wheel and SSH-host-auth integrated "
    "runner with a non-serializable capability and a new schema does not exist"
)


class FailureDomainRotationError(RuntimeError):
    """A diagnostic input is invalid or a formal operation is unavailable."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _now_utc() -> str:
    """Return tool-owned UTC; callers cannot submit freshness timestamps."""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise FailureDomainRotationError(f"{label} is not a lowercase SHA-256")
    return value


def _require_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise FailureDomainRotationError(f"{label} is invalid")
    return value


def _utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or "T" not in value:
        raise FailureDomainRotationError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise FailureDomainRotationError(f"{label} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise FailureDomainRotationError(f"{label} must be UTC")
    if parsed.isoformat() not in {value, value.replace("Z", "+00:00")}:
        raise FailureDomainRotationError(f"{label} is not strict ISO-8601")
    return parsed


def _fresh(observed_at: str, *, now: str, max_age_seconds: int) -> None:
    if (
        not isinstance(max_age_seconds, int)
        or isinstance(max_age_seconds, bool)
        or max_age_seconds <= 0
    ):
        raise FailureDomainRotationError("max age must be a positive integer")
    observed = _utc(observed_at, label="observed_at")
    current_time = _utc(now, label="now")
    age = (current_time - observed).total_seconds()
    if age < 0 or age > max_age_seconds:
        raise FailureDomainRotationError("observation is future-dated or stale")


def _producer(producer_id: str, producer_tool_sha256: str) -> dict[str, str]:
    return {
        "producer_id": _require_id(producer_id, label="producer ID"),
        "producer_tool_sha256": _require_sha(
            producer_tool_sha256, label="producer tool hash"
        ),
    }


def _module_producer(producer_id: str, *, tool_path: Path | None = None) -> dict[str, str]:
    selected = Path(tool_path or __file__).resolve(strict=True)
    return _producer(producer_id, _sha(selected.read_bytes()))


def _production_tool_path() -> Path:
    from . import production_host_facts_cli

    return Path(production_host_facts_cli.__file__).resolve(strict=True)


def _verify_producer(
    value: object, *, expected_id: str, tool_path: Path | None = None
) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "producer_id",
        "producer_tool_sha256",
    }:
        raise FailureDomainRotationError(f"{expected_id} producer identity is not closed")
    normalized = _producer(
        str(value.get("producer_id")), str(value.get("producer_tool_sha256"))
    )
    if normalized != _module_producer(expected_id, tool_path=tool_path):
        raise FailureDomainRotationError(
            f"{expected_id} producer does not match diagnostic module bytes"
        )
    return normalized


def _strict_root(path: Path) -> Path:
    ensure_no_reparse_components(path)
    root = path.resolve(strict=True)
    ensure_no_reparse_components(root)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
        raise FailureDomainRotationError("recovery root is not a real directory")
    return root


def _contained(path: Path, root: Path, *, must_exist: bool) -> Path:
    ensure_no_reparse_components(path)
    resolved = path.resolve(strict=must_exist)
    if resolved == root or not resolved.is_relative_to(root):
        raise FailureDomainRotationError("diagnostic path escaped recovery root")
    ensure_no_reparse_components(resolved)
    return resolved


def _stable_file(path: Path, root: Path, *, label: str) -> tuple[Path, bytes]:
    """Read a single-link regular file and detect replacement during the read."""

    target = _contained(path, root, must_exist=True)
    before = target.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat_is_reparse_point(before)
        or before.st_nlink != 1
    ):
        raise FailureDomainRotationError(f"{label} is not a single-link regular file")
    raw = target.read_bytes()
    after = target.lstat()
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_nlink,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_nlink,
    )
    if identity_before != identity_after or len(raw) != after.st_size:
        raise FailureDomainRotationError(f"{label} changed while being read")
    return target, raw


def _canonical_object(raw: bytes, *, label: str) -> dict[str, object]:
    if len(raw) > MAX_JSON_BYTES:
        raise FailureDomainRotationError(f"{label} exceeds the JSON byte limit")

    def closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise FailureDomainRotationError(
                    f"{label} contains a duplicate JSON key"
                )
            value[key] = item
        return value

    def invalid_constant(_: str) -> object:
        raise FailureDomainRotationError(f"{label} contains a non-finite number")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=closed_object,
            parse_constant=invalid_constant,
        )
    except FailureDomainRotationError:
        raise
    except (UnicodeError, ValueError, RecursionError, MemoryError) as error:
        raise FailureDomainRotationError(f"{label} is not UTF-8 JSON") from error
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise FailureDomainRotationError(f"{label} exceeds the JSON depth limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    try:
        encoded = canonical_bytes(value)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise FailureDomainRotationError(f"{label} cannot be canonicalized") from error
    if not isinstance(value, dict) or raw != encoded:
        raise FailureDomainRotationError(f"{label} is not canonical JSON")
    return value


def _verify_attestation(raw: bytes) -> dict[str, object]:
    value = _canonical_object(raw, label="current attestation")
    expected = {
        "schema_version",
        "observed_at",
        "production_host_facts_sha256",
        "recovery_host_facts_sha256",
        "production",
        "recovery",
        "independence_probe",
        "verdict",
        "attestation_sha256",
    }
    if set(value) != expected or value.get("schema_version") != ATTESTATION_SCHEMA:
        raise FailureDomainRotationError("current attestation schema is not closed")
    _utc(value.get("observed_at"), label="current attestation observed_at")
    try:
        rebuilt = attest_failure_domain(
            production_facts=value["production"],
            recovery_facts=value["recovery"],
            independence_probe=value["independence_probe"],
            observed_at=str(value["observed_at"]),
        )
    except (FailureDomainError, TypeError) as error:
        raise FailureDomainRotationError("current attestation is invalid") from error
    actual_payload = dict(value)
    actual_payload.pop("attestation_sha256")
    if value["attestation_sha256"] != rebuilt.sha256 or actual_payload != rebuilt.payload:
        raise FailureDomainRotationError("current attestation identity differs")
    return value


def _verify_challenge(raw: bytes, *, now: str) -> dict[str, object]:
    """Validate a legacy synthetic receipt; it never grants formal authority."""

    value = _canonical_object(raw, label="synthetic refresh challenge")
    expected = {
        "schema_version",
        "challenge_id",
        "issued_at",
        "issuer",
        "challenge_sha256",
    }
    if set(value) != expected or value.get("schema_version") != CHALLENGE_SCHEMA:
        raise FailureDomainRotationError("synthetic challenge schema is not closed")
    claimed = value.pop("challenge_sha256")
    if claimed != _sha(canonical_bytes(value)):
        raise FailureDomainRotationError("synthetic challenge identity differs")
    value["challenge_sha256"] = claimed
    _require_id(value["challenge_id"], label="challenge ID")
    _verify_producer(
        value["issuer"], expected_id="qrh-failure-domain-challenge-issuer"
    )
    _fresh(str(value["issued_at"]), now=now, max_age_seconds=CAPTURE_TTL_SECONDS)
    return value


def _verify_capture(
    raw: bytes,
    *,
    source_kind: str,
    challenge: Mapping[str, object],
    challenge_file_sha256: str,
    now: str,
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate a legacy synthetic capture without accepting it as authority."""

    if source_kind not in _SOURCE_PRODUCERS:
        raise FailureDomainRotationError("synthetic capture kind is invalid")
    value = _canonical_object(raw, label=f"synthetic {source_kind} capture")
    expected = {
        "schema_version",
        "source_kind",
        "challenge_id",
        "challenge_sha256",
        "captured_at",
        "producer",
        "source_sha256",
        "source",
        "capture_sha256",
    }
    if (
        set(value) != expected
        or value.get("schema_version") != CAPTURE_SCHEMA
        or value.get("source_kind") != source_kind
    ):
        raise FailureDomainRotationError(
            f"synthetic {source_kind} capture schema is not closed"
        )
    claimed = value.pop("capture_sha256")
    if claimed != _sha(canonical_bytes(value)):
        raise FailureDomainRotationError(f"synthetic {source_kind} capture differs")
    value["capture_sha256"] = claimed
    if (
        value["challenge_id"] != challenge["challenge_id"]
        or value["challenge_sha256"] != challenge_file_sha256
    ):
        raise FailureDomainRotationError("synthetic captures do not bind one challenge")
    producer_tool = _production_tool_path() if source_kind == "production_facts" else None
    _verify_producer(
        value["producer"],
        expected_id=_SOURCE_PRODUCERS[source_kind],
        tool_path=producer_tool,
    )
    _fresh(str(value["captured_at"]), now=now, max_age_seconds=CAPTURE_TTL_SECONDS)
    source = value["source"]
    if not isinstance(source, dict):
        raise FailureDomainRotationError(f"synthetic {source_kind} source is not an object")
    source_raw = canonical_bytes(source)
    if value["source_sha256"] != _sha(source_raw):
        raise FailureDomainRotationError(f"synthetic {source_kind} source hash differs")
    try:
        if source_kind == "production_facts":
            verified = verify_host_facts(source, expected_role="production")
        elif source_kind == "recovery_facts":
            verified = verify_host_facts(source, expected_role="recovery")
        else:
            verified = verify_independence_probe(source)
    except FailureDomainError as error:
        raise FailureDomainRotationError(
            f"synthetic {source_kind} source is invalid"
        ) from error
    return value, verified


def _verify_observation(
    raw: bytes, *, now: str, max_age_seconds: int
) -> dict[str, object]:
    """Validate a legacy synthetic observation; never return formal readiness."""

    value = _canonical_object(raw, label="synthetic observation receipt")
    expected = {
        "schema_version",
        "observation_id",
        "observed_at",
        "producer",
        "challenge_id",
        "challenge_path",
        "challenge_file_sha256",
        "challenge_sha256",
        "source_capture_path",
        "source_capture_file_sha256",
        "source_file_sha256",
        "source_captured_at",
        "production",
        "recovery",
        "independence_probe",
        "next_attestation_sha256",
        "observation_sha256",
    }
    if set(value) != expected or value.get("schema_version") != OBSERVATION_SCHEMA:
        raise FailureDomainRotationError("synthetic observation schema is not closed")
    claimed = value.pop("observation_sha256")
    if claimed != _sha(canonical_bytes(value)):
        raise FailureDomainRotationError("synthetic observation identity differs")
    value["observation_sha256"] = claimed
    _require_id(value["observation_id"], label="observation ID")
    _verify_producer(value["producer"], expected_id="qrh-failure-domain-observer")
    _require_id(value["challenge_id"], label="challenge ID")
    _require_sha(value["challenge_file_sha256"], label="challenge file hash")
    _require_sha(value["challenge_sha256"], label="challenge identity")
    source_names = {"production_facts", "recovery_facts", "independence_probe"}
    if not isinstance(value["challenge_path"], str) or not value["challenge_path"]:
        raise FailureDomainRotationError("synthetic challenge path is invalid")
    for field in (
        "source_capture_path",
        "source_capture_file_sha256",
        "source_file_sha256",
        "source_captured_at",
    ):
        child = value[field]
        if not isinstance(child, dict) or set(child) != source_names:
            raise FailureDomainRotationError(f"synthetic observation {field} is not closed")
    embedded_sources = {
        "production_facts": value["production"],
        "recovery_facts": value["recovery"],
        "independence_probe": value["independence_probe"],
    }
    capture_times: list[datetime] = []
    for name in sorted(source_names):
        if (
            not isinstance(value["source_capture_path"][name], str)
            or not value["source_capture_path"][name]
        ):
            raise FailureDomainRotationError(f"synthetic {name} capture path is invalid")
        _require_sha(
            value["source_capture_file_sha256"][name],
            label=f"{name} capture file hash",
        )
        expected_source_hash = _sha(canonical_bytes(embedded_sources[name]))
        if value["source_file_sha256"][name] != expected_source_hash:
            raise FailureDomainRotationError(f"synthetic {name} source hash differs")
        _fresh(
            str(value["source_captured_at"][name]),
            now=str(value["observed_at"]),
            max_age_seconds=CAPTURE_TTL_SECONDS,
        )
        capture_times.append(
            _utc(value["source_captured_at"][name], label=f"{name} captured_at")
        )
    if (max(capture_times) - min(capture_times)).total_seconds() > CAPTURE_MAX_SKEW_SECONDS:
        raise FailureDomainRotationError("synthetic capture clock skew exceeds policy")
    _fresh(str(value["observed_at"]), now=now, max_age_seconds=max_age_seconds)
    try:
        production = verify_host_facts(value["production"], expected_role="production")
        recovery = verify_host_facts(value["recovery"], expected_role="recovery")
        probe = verify_independence_probe(value["independence_probe"])
        built = attest_failure_domain(
            production_facts=production,
            recovery_facts=recovery,
            independence_probe=probe,
            observed_at=str(value["observed_at"]),
        )
    except (FailureDomainError, TypeError) as error:
        raise FailureDomainRotationError(
            "synthetic observation facts cannot be attested"
        ) from error
    if value["next_attestation_sha256"] != built.sha256:
        raise FailureDomainRotationError("synthetic next attestation differs")
    return value


def _verify_observation_lineage(
    *,
    root: Path,
    observation_path: Path,
    observation: Mapping[str, object],
    now: str,
) -> None:
    """Read and validate the complete legacy synthetic observation lineage."""

    expected_observation_path = (
        root
        / "failure-domain"
        / "observations"
        / f"{observation['challenge_id']}.json"
    )
    if observation_path != expected_observation_path:
        raise FailureDomainRotationError("synthetic observation path differs")
    challenge_path = _contained(
        root / str(observation["challenge_path"]), root, must_exist=True
    )
    _, challenge_raw = _stable_file(
        challenge_path, root, label="synthetic challenge lineage"
    )
    if _sha(challenge_raw) != observation["challenge_file_sha256"]:
        raise FailureDomainRotationError("synthetic challenge file hash differs")
    challenge = _verify_challenge(challenge_raw, now=now)
    if (
        challenge["challenge_id"] != observation["challenge_id"]
        or challenge["challenge_sha256"] != observation["challenge_sha256"]
    ):
        raise FailureDomainRotationError("synthetic challenge lineage differs")
    embedded = {
        "production_facts": observation["production"],
        "recovery_facts": observation["recovery"],
        "independence_probe": observation["independence_probe"],
    }
    capture_paths = observation["source_capture_path"]
    if not isinstance(capture_paths, dict):
        raise FailureDomainRotationError("synthetic capture path map is invalid")
    for kind, relative in sorted(capture_paths.items()):
        capture_path = _contained(root / str(relative), root, must_exist=True)
        _, capture_raw = _stable_file(
            capture_path, root, label=f"synthetic {kind} capture lineage"
        )
        if _sha(capture_raw) != observation["source_capture_file_sha256"][kind]:
            raise FailureDomainRotationError(f"synthetic {kind} file hash differs")
        capture, source = _verify_capture(
            capture_raw,
            source_kind=kind,
            challenge=challenge,
            challenge_file_sha256=_sha(challenge_raw),
            now=now,
        )
        if (
            source != embedded[kind]
            or capture["captured_at"] != observation["source_captured_at"][kind]
            or capture["source_sha256"] != observation["source_file_sha256"][kind]
        ):
            raise FailureDomainRotationError(f"synthetic {kind} lineage differs")


def _verify_intent(raw: bytes) -> dict[str, object]:
    """Parse a historical synthetic intent without applying it."""

    value = _canonical_object(raw, label="synthetic rotation intent")
    expected = {
        "schema_version", "rotation_id", "prepared_at", "producer",
        "current_path", "observation_path", "intent_path", "archive_path",
        "completion_path", "expected_current_file_sha256",
        "expected_current_attestation_sha256", "expected_observation_file_sha256",
        "expected_observation_sha256", "next_attestation",
        "next_attestation_file_sha256", "intent_sha256",
    }
    if set(value) != expected or value.get("schema_version") != INTENT_SCHEMA:
        raise FailureDomainRotationError("synthetic intent schema is not closed")
    claimed = value.pop("intent_sha256")
    if claimed != _sha(canonical_bytes(value)):
        raise FailureDomainRotationError("synthetic intent identity differs")
    value["intent_sha256"] = claimed
    _require_id(value["rotation_id"], label="rotation ID")
    _utc(value["prepared_at"], label="prepared_at")
    _verify_producer(value["producer"], expected_id="qrh-failure-domain-rotator")
    for key in (
        "expected_current_file_sha256", "expected_current_attestation_sha256",
        "expected_observation_file_sha256", "expected_observation_sha256",
        "next_attestation_file_sha256", "intent_sha256",
    ):
        _require_sha(value[key], label=key)
    return value


def _verify_completion(raw: bytes) -> dict[str, object]:
    """Parse a historical synthetic completion without granting authority."""

    value = _canonical_object(raw, label="synthetic rotation completion")
    expected = {
        "schema_version", "rotation_id", "completed_at", "producer",
        "current_path", "intent_path", "observation_path", "completion_path",
        "intent_file_sha256", "intent_sha256", "observation_file_sha256",
        "observation_sha256", "old_current_file_sha256",
        "old_attestation_archive_path", "old_attestation_archive_sha256",
        "new_current_file_sha256", "new_attestation_sha256", "verdict",
        "completion_sha256",
    }
    if set(value) != expected or value.get("schema_version") != COMPLETION_SCHEMA:
        raise FailureDomainRotationError("synthetic completion schema is not closed")
    claimed = value.pop("completion_sha256")
    if claimed != _sha(canonical_bytes(value)):
        raise FailureDomainRotationError("synthetic completion identity differs")
    value["completion_sha256"] = claimed
    _require_id(value["rotation_id"], label="completion rotation ID")
    _utc(value["completed_at"], label="completed_at")
    _verify_producer(value["producer"], expected_id="qrh-failure-domain-rotator")
    for key in ("current_path", "intent_path", "observation_path", "completion_path"):
        if not isinstance(value[key], str) or not value[key]:
            raise FailureDomainRotationError(f"synthetic completion {key} is invalid")
    for key in (
        "intent_file_sha256", "intent_sha256", "observation_file_sha256",
        "observation_sha256", "old_current_file_sha256",
        "old_attestation_archive_sha256", "new_current_file_sha256",
        "new_attestation_sha256", "completion_sha256",
    ):
        _require_sha(value[key], label=key)
    if value["verdict"] != "rotated":
        raise FailureDomainRotationError("synthetic completion verdict is invalid")
    return value


def _same_path(left: object, right: Path) -> bool:
    if not isinstance(left, str):
        return False
    if PureWindowsPath(left).drive or PureWindowsPath(str(right)).drive:
        return PureWindowsPath(left) == PureWindowsPath(str(right))
    return Path(left) == right


def _not_ready(operation: str) -> FailureDomainRotationError:
    try:
        require_failure_domain_authority()
    except FailureDomainAuthorityNotReady as error:
        return FailureDomainRotationError(
            f"{operation}: {_FORMAL_NOT_READY}; {error}"
        )
    raise AssertionError("formal failure-domain authority unexpectedly returned")


def prepare_rotation(
    *, mode: str, recovery_root: Path, current_path: Path,
    observation_path: Path, expected_current_file_sha256: str,
    expected_observation_file_sha256: str, max_age_seconds: int,
    rotation_id: str, intent_path: Path,
) -> dict[str, object]:
    """Inspect legacy material read-only or reject formal prepare before I/O."""

    del intent_path
    if mode == "prepare":
        raise _not_ready("rotate-prepare --mode prepare")
    if mode != "inspect":
        raise FailureDomainRotationError("rotation mode is invalid")
    root = _strict_root(recovery_root)
    now = _now_utc()
    _, current_raw = _stable_file(
        current_path, root, label="diagnostic current attestation"
    )
    observation_target, observation_raw = _stable_file(
        observation_path, root, label="diagnostic synthetic observation"
    )
    if _sha(current_raw) != _require_sha(
        expected_current_file_sha256, label="expected current hash"
    ):
        raise FailureDomainRotationError("current attestation file hash differs")
    if _sha(observation_raw) != _require_sha(
        expected_observation_file_sha256, label="expected observation hash"
    ):
        raise FailureDomainRotationError("synthetic observation file hash differs")
    current_value = _verify_attestation(current_raw)
    observation = _verify_observation(
        observation_raw, now=now, max_age_seconds=max_age_seconds
    )
    _verify_observation_lineage(
        root=root, observation_path=observation_target,
        observation=observation, now=now,
    )
    if (
        observation["production"] != current_value["production"]
        or observation["recovery"] != current_value["recovery"]
        or observation["independence_probe"] != current_value["independence_probe"]
    ):
        raise FailureDomainRotationError(
            "synthetic observation differs from current diagnostic identities"
        )
    if not _same_path(
        observation["production"]["canonical_path"],
        Path(r"D:\quant\quant_platform"),
    ):
        raise FailureDomainRotationError("production diagnostic is not exact-D")
    if not _same_path(observation["recovery"]["canonical_path"], root):
        raise FailureDomainRotationError("recovery diagnostic belongs to another root")
    rotation = _require_id(rotation_id, label="rotation ID")
    return {
        "schema_version": "qrh-failure-domain-rotation-inspection/v1",
        "status": "DIAGNOSTIC_ONLY", "authority": False,
        "rotation_readiness": ROTATION_READINESS,
        "diagnostic_readiness": DIAGNOSTIC_READINESS,
        "rotation_id": rotation, "current_file_sha256": _sha(current_raw),
        "current_attestation_sha256": current_value["attestation_sha256"],
        "observation_file_sha256": _sha(observation_raw),
        "observation_sha256": observation["observation_sha256"],
        "would_be_attestation_sha256": observation["next_attestation_sha256"],
    }


def apply_rotation(**_: object) -> dict[str, object]:
    """Reject formal apply; no mutating implementation ships in the package."""

    raise _not_ready("rotate-apply")


def verify_current_attestation(**_: object) -> dict[str, object]:
    """Reject formal completion verification until the integrated runner exists."""

    raise _not_ready("verify-current")


def diagnose_legacy_current_attestation(
    *, recovery_root: Path, current_path: Path,
    expected_current_file_sha256: str, max_age_seconds: int,
) -> dict[str, object]:
    """Validate a current attestation read-only, without refresh authority."""

    root = _strict_root(recovery_root)
    _, raw = _stable_file(current_path, root, label="legacy current attestation")
    if _sha(raw) != _require_sha(
        expected_current_file_sha256, label="expected current hash"
    ):
        raise FailureDomainRotationError("current attestation file hash differs")
    value = _verify_attestation(raw)
    _fresh(str(value["observed_at"]), now=_now_utc(), max_age_seconds=max_age_seconds)
    if not _same_path(
        value["production"]["canonical_path"], Path(r"D:\quant\quant_platform")
    ):
        raise FailureDomainRotationError("production diagnostic is not exact-D")
    if not _same_path(value["recovery"]["canonical_path"], root):
        raise FailureDomainRotationError("attestation belongs to another recovery root")
    return {
        **value, "status": "DIAGNOSTIC_ONLY", "authority": False,
        "legacy_diagnostic_only": True, "rotation_readiness": ROTATION_READINESS,
    }


def diagnostic_source_manifest(
    *, repo_root: Path, repo_relative_paths: Sequence[str]
) -> dict[str, object]:
    """Compute the reproducible, read-only UTF-8/NUL source manifest."""

    root = _strict_root(repo_root)
    normalized: list[str] = []
    for supplied in repo_relative_paths:
        value = unicodedata.normalize("NFC", supplied.replace("\\", "/"))
        candidate = PurePosixPath(value)
        if (
            value != supplied or value in {"", "."} or candidate.is_absolute()
            or ".." in candidate.parts or value != candidate.as_posix()
        ):
            raise FailureDomainRotationError(
                "manifest path must be an NFC, slash-normalized repo-relative path"
            )
        normalized.append(value)
    if len(normalized) != len(set(normalized)) or not normalized:
        raise FailureDomainRotationError("manifest paths must be nonempty and unique")
    entries: list[dict[str, object]] = []
    payload = bytearray()
    for relative in sorted(normalized, key=lambda item: item.encode("utf-8")):
        _, raw = _stable_file(root / PurePosixPath(relative), root, label="manifest source")
        digest = _sha(raw)
        payload.extend(relative.encode("utf-8"))
        payload.extend(b"\0")
        payload.extend(digest.encode("ascii"))
        payload.extend(b"\0")
        entries.append(
            {"path": relative, "file_sha256": digest, "size_bytes": len(raw)}
        )
    return {
        "schema_version": SOURCE_MANIFEST_SCHEMA, "status": "DIAGNOSTIC_ONLY",
        "authority": False,
        "algorithm": "sort UTF-8 NFC repo paths; append path NUL sha256hex NUL",
        "entries": entries, "manifest_sha256": _sha(bytes(payload)),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    challenge = commands.add_parser("issue-challenge")
    challenge.add_argument("--recovery-root", type=Path, required=True)
    recovery_capture = commands.add_parser("capture-recovery-facts")
    recovery_capture.add_argument("--recovery-root", type=Path, required=True)
    recovery_capture.add_argument("--challenge", type=Path, required=True)
    probe_capture = commands.add_parser("capture-independence-probe")
    probe_capture.add_argument("--recovery-root", type=Path, required=True)
    probe_capture.add_argument("--challenge", type=Path, required=True)
    probe_capture.add_argument("--bundle-root", type=Path, required=True)
    probe_capture.add_argument("--materialization-event", type=Path, required=True)
    probe_capture.add_argument("--probe-tool", type=Path, required=True)
    observe = commands.add_parser("observe")
    observe.add_argument("--recovery-root", type=Path, required=True)
    observe.add_argument("--challenge", type=Path, required=True)
    observe.add_argument("--production-capture", type=Path, required=True)
    observe.add_argument("--recovery-capture", type=Path, required=True)
    observe.add_argument("--independence-capture", type=Path, required=True)
    observe.add_argument("--output", type=Path, required=True)
    prepare = commands.add_parser("rotate-prepare")
    prepare.add_argument("--mode", choices=("inspect", "prepare"), required=True)
    prepare.add_argument("--recovery-root", type=Path, required=True)
    prepare.add_argument("--current", type=Path, required=True)
    prepare.add_argument("--observation", type=Path, required=True)
    prepare.add_argument("--expected-current-file-sha256", required=True)
    prepare.add_argument("--expected-observation-file-sha256", required=True)
    prepare.add_argument("--max-age-seconds", type=int, required=True)
    prepare.add_argument("--rotation-id", required=True)
    prepare.add_argument("--intent-output", type=Path, required=True)
    apply_parser = commands.add_parser("rotate-apply")
    apply_parser.add_argument("--recovery-root", type=Path, required=True)
    apply_parser.add_argument("--current", type=Path, required=True)
    apply_parser.add_argument("--observation", type=Path, required=True)
    apply_parser.add_argument("--intent", type=Path, required=True)
    apply_parser.add_argument("--expected-current-file-sha256", required=True)
    apply_parser.add_argument("--expected-observation-file-sha256", required=True)
    apply_parser.add_argument("--expected-intent-file-sha256", required=True)
    apply_parser.add_argument("--max-age-seconds", type=int, required=True)
    verify = commands.add_parser("verify-current")
    verify.add_argument("--recovery-root", type=Path, required=True)
    verify.add_argument("--current", type=Path, required=True)
    verify.add_argument("--expected-current-file-sha256", required=True)
    verify.add_argument("--completion", type=Path, required=True)
    verify.add_argument("--expected-completion-file-sha256", required=True)
    verify.add_argument("--max-age-seconds", type=int, required=True)
    legacy = commands.add_parser("diagnose-legacy-current")
    legacy.add_argument("--recovery-root", type=Path, required=True)
    legacy.add_argument("--current", type=Path, required=True)
    legacy.add_argument("--expected-current-file-sha256", required=True)
    legacy.add_argument("--max-age-seconds", type=int, required=True)
    manifest = commands.add_parser("source-manifest")
    manifest.add_argument("--repo-root", type=Path, required=True)
    manifest.add_argument("--path", action="append", required=True)
    return parser


def _not_ready_result(command: str, reason: str) -> dict[str, object]:
    return {
        "status": "NOT_READY", "authority": False, "command": command,
        "rotation_readiness": ROTATION_READINESS,
        "diagnostic_readiness": DIAGNOSTIC_READINESS,
        "reason": reason,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    disabled_producers = {
        "issue-challenge", "capture-recovery-facts",
        "capture-independence-probe", "observe",
    }
    try:
        if args.command in disabled_producers:
            raise _not_ready(f"{args.command} synthetic producer is not a formal source")
        if args.command == "rotate-prepare":
            result = prepare_rotation(
                mode=args.mode, recovery_root=args.recovery_root,
                current_path=args.current, observation_path=args.observation,
                expected_current_file_sha256=args.expected_current_file_sha256,
                expected_observation_file_sha256=args.expected_observation_file_sha256,
                max_age_seconds=args.max_age_seconds, rotation_id=args.rotation_id,
                intent_path=args.intent_output,
            )
        elif args.command == "rotate-apply":
            raise _not_ready("rotate-apply")
        elif args.command == "verify-current":
            raise _not_ready("verify-current")
        elif args.command == "diagnose-legacy-current":
            result = diagnose_legacy_current_attestation(
                recovery_root=args.recovery_root, current_path=args.current,
                expected_current_file_sha256=args.expected_current_file_sha256,
                max_age_seconds=args.max_age_seconds,
            )
        else:
            result = diagnostic_source_manifest(
                repo_root=args.repo_root, repo_relative_paths=args.path
            )
    except FailureDomainRotationError as error:
        status = "NOT_READY" if "FAKE_ONLY/NOT_READY" in str(error) else "FAIL_CLOSED"
        print(json.dumps(
            _not_ready_result(args.command, str(error)) | {"status": status},
            ensure_ascii=False, sort_keys=True,
        ))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


__all__ = [
    "CAPTURE_SCHEMA", "CHALLENGE_SCHEMA", "COMPLETION_SCHEMA",
    "DIAGNOSTIC_READINESS", "INTENT_SCHEMA", "OBSERVATION_SCHEMA",
    "ROTATION_READINESS", "SOURCE_MANIFEST_SCHEMA",
    "FailureDomainRotationError", "apply_rotation",
    "diagnose_legacy_current_attestation", "diagnostic_source_manifest", "main",
    "prepare_rotation", "verify_current_attestation",
]


if __name__ == "__main__":
    raise SystemExit(main())
