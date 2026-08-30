"""Fail-closed, public-synthetic architecture review preregistration.

No production transport is shipped in this module.  It freezes four canonical
requests, binds them to one canonical campaign manifest, and provides a durable
SQLite CAS ledger for simulation and later independently approved integration.
Model-like responses are tested through a credential-free parser.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Iterable
from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point

from .contracts import canonical_json


DS_REVIEW_API_HOST = "api.deepseek.com"
DS_REVIEW_API_PATH = "/chat/completions"
DS_REVIEW_MODEL_ALIAS = "deepseek-v4-pro"
DS_REVIEW_PROVIDER_REVISION = "DeepSeek-V4-Pro-0813"
DS_REVIEW_DOSSIER_SCHEMA = "qrh-public-synthetic-architecture-dossier/v2"
DS_REVIEW_MANIFEST_SCHEMA = "qrh-ds-architecture-review-campaign/v2"
DS_REVIEW_OUTPUT_SCHEMA = "qrh-ds-architecture-review-output/v2"
DS_REVIEW_RECEIPT_SCHEMA = "qrh-ds-architecture-review-receipt/v2"
DS_REVIEW_LEDGER_SCHEMA = "qrh-ds-architecture-review-ledger/v1"
DS_REVIEW_OVERALL_DEADLINE_SECONDS = 90.0
DS_REVIEW_MAX_REQUEST_BYTES = 96 * 1024
DS_REVIEW_MAX_RESPONSE_BYTES = 256 * 1024
DS_REVIEW_MAX_JSON_DEPTH = 32

# A production HTTP/keyring child is intentionally absent.  Changing this
# constant is insufficient to enable transport; there is no send implementation.
EXTERNAL_TRANSPORT_STATE = "DISABLED_PENDING_INDEPENDENT_APPROVAL"

ROUND_IDS = (
    "round-1-blind-review",
    "round-2-stress-matrix-critique",
    "round-3-results-and-minimal-change",
    "round-4-final-dissent",
)

MECHANISMS = (
    "SEMANTIC_JOB_CAS",
    "MIRROR_POINTER_SERIALIZATION",
    "MCP_INPUT_BOUNDS",
    "MCP_BOUNDED_MATERIALIZATION",
    "AUTHORITY_LOCK_RECOVERY",
    "ARTIFACT_INDEX_IDENTITY",
    "SQLITE_WRITER_RECOVERY",
    "TRANSFER_CAPACITY_BOUND",
)
MECHANISM_IDS = tuple(f"M{index:02d}" for index in range(1, len(MECHANISMS) + 1))

INVARIANTS = (
    "EXACTLY_ONE_PROVIDER_SIDE_EFFECT",
    "ONE_CURRENT_IDENTITY",
    "REJECT_OVERSIZE_BEFORE_WORK",
    "RESULT_LIMIT_BOUNDS_MEMORY",
    "KILL_RECOVERS_WITHOUT_MANUAL_DELETE",
    "ARTIFACT_AND_INDEX_IDENTITY_MATCH",
    "OLD_OR_NEW_COMPLETE_STATE_ONLY",
    "WIRE_BYTES_BELOW_FIXED_CAP",
)
INVARIANT_IDS = tuple(f"I{index:02d}" for index in range(1, len(INVARIANTS) + 1))

STRESS_CASES = (
    "TWO_WORKERS_SAME_JOB",
    "THIRTY_TWO_PROCESSES_SHARED_MIRROR",
    "OVERSIZE_LINE_QUERY_CURSOR_DEPTH",
    "TEN_X_RECORDS_FIXED_RESULT_LIMIT",
    "KILL_DURING_LOCK_OWNERSHIP",
    "INDEX_UPGRADE_AND_ROLLBACK",
    "KILL_AT_DURABLE_WRITE_BOUNDARIES",
    "ONE_THOUSAND_HOT_REQUESTS",
)

OUTCOMES = (
    "DUPLICATE_SIDE_EFFECT",
    "SPLIT_POINTER",
    "UNBOUNDED_ACCEPT",
    "SUPERLINEAR_MEMORY",
    "STALE_LOCK",
    "IDENTITY_DRIFT",
    "PARTIAL_STATE",
    "CAP_EXCEEDED",
)


@dataclass(frozen=True, slots=True)
class SyntheticObservation:
    """Deeply immutable, scalar-only synthetic scenario specification."""

    scenario_id: str
    mechanism_id: str
    mechanism: str
    behavior: str
    risk_class: str
    stress_case: str
    invariant_id: str
    invariant: str
    process_count: int
    record_scale: int
    outcome: str

    def validate(self, ordinal: int) -> None:
        rows = _canonical_scenario_rows()
        if type(ordinal) is not int or not 0 <= ordinal < len(rows):
            raise DossierPolicyError("synthetic scenario ordinal is invalid")
        if self != rows[ordinal]:
            raise DossierPolicyError("synthetic scenario mapping is not the frozen mapping")
        scalar_values = asdict(self).values()
        if any(type(value) not in (str, int) for value in scalar_values):
            raise DossierPolicyError("synthetic scenario fields must be immutable scalars")
        if type(self.process_count) is not int or type(self.record_scale) is not int:
            raise DossierPolicyError("synthetic numeric fields must be exact integers")


# These canonical byte strings, together with hash literals embedded in the
# replay functions below, are the normative source.  Exported dataclass/dict
# views are compatibility snapshots only and are never trusted by prepare or
# validation boundaries.
_SCENARIO_SPEC_BYTES = (
    b'{"rows":[{"behavior":"CONCURRENT_OWNER_SELECTION","invariant":"EXACTLY_ONE_PROVIDER_SIDE_EFFECT","invariant_id":"I01","mechanism":"SEMANTIC_JOB_CAS","mechanism_id":"M01","outcome":"DUPLICATE_SIDE_EFFECT","process_count":16,"record_scale":100,"risk_class":"CONCURRENCY","scenario_id":"S01","stress_case":"TWO_WORKERS_SAME_JOB"},'
    b'{"behavior":"CURRENT_POINTER_PUBLICATION","invariant":"ONE_CURRENT_IDENTITY","invariant_id":"I02","mechanism":"MIRROR_POINTER_SERIALIZATION","mechanism_id":"M02","outcome":"SPLIT_POINTER","process_count":32,"record_scale":1000,"risk_class":"CONCURRENCY","scenario_id":"S02","stress_case":"THIRTY_TWO_PROCESSES_SHARED_MIRROR"},'
    b'{"behavior":"PREWORK_INPUT_REJECTION","invariant":"REJECT_OVERSIZE_BEFORE_WORK","invariant_id":"I03","mechanism":"MCP_INPUT_BOUNDS","mechanism_id":"M03","outcome":"UNBOUNDED_ACCEPT","process_count":8,"record_scale":10000,"risk_class":"RESOURCE","scenario_id":"S03","stress_case":"OVERSIZE_LINE_QUERY_CURSOR_DEPTH"},'
    b'{"behavior":"FIXED_LIMIT_RESULT_SELECTION","invariant":"RESULT_LIMIT_BOUNDS_MEMORY","invariant_id":"I04","mechanism":"MCP_BOUNDED_MATERIALIZATION","mechanism_id":"M04","outcome":"SUPERLINEAR_MEMORY","process_count":8,"record_scale":100000,"risk_class":"RESOURCE","scenario_id":"S04","stress_case":"TEN_X_RECORDS_FIXED_RESULT_LIMIT"},'
    b'{"behavior":"TERMINATED_OWNER_RECOVERY","invariant":"KILL_RECOVERS_WITHOUT_MANUAL_DELETE","invariant_id":"I05","mechanism":"AUTHORITY_LOCK_RECOVERY","mechanism_id":"M05","outcome":"STALE_LOCK","process_count":2,"record_scale":100,"risk_class":"DURABILITY","scenario_id":"S05","stress_case":"KILL_DURING_LOCK_OWNERSHIP"},'
    b'{"behavior":"VERSION_PAIR_VALIDATION","invariant":"ARTIFACT_AND_INDEX_IDENTITY_MATCH","invariant_id":"I06","mechanism":"ARTIFACT_INDEX_IDENTITY","mechanism_id":"M06","outcome":"IDENTITY_DRIFT","process_count":2,"record_scale":10000,"risk_class":"CONSISTENCY","scenario_id":"S06","stress_case":"INDEX_UPGRADE_AND_ROLLBACK"},'
    b'{"behavior":"DURABLE_COMMIT_RECOVERY","invariant":"OLD_OR_NEW_COMPLETE_STATE_ONLY","invariant_id":"I07","mechanism":"SQLITE_WRITER_RECOVERY","mechanism_id":"M07","outcome":"PARTIAL_STATE","process_count":16,"record_scale":1000,"risk_class":"DURABILITY","scenario_id":"S07","stress_case":"KILL_AT_DURABLE_WRITE_BOUNDARIES"},'
    b'{"behavior":"FIXED_CAP_TRANSFER","invariant":"WIRE_BYTES_BELOW_FIXED_CAP","invariant_id":"I08","mechanism":"TRANSFER_CAPACITY_BOUND","mechanism_id":"M08","outcome":"CAP_EXCEEDED","process_count":32,"record_scale":100000,"risk_class":"RESOURCE","scenario_id":"S08","stress_case":"ONE_THOUSAND_HOT_REQUESTS"}],"schema_version":"qrh-ds-scenario-spec/v1"}'
)
_SCENARIO_SPEC_SHA256 = "b0ec6268b151a86201ee963de0a783af70df323c9f7d8f670cdfcf8f61e9da51"

_ROUND_OBJECTIVE_SPEC_BYTES = (
    b'{"rounds":[{"objective":"FIND_FLAWS_AND_MISSING_FALSIFICATION_TESTS_WITHOUT_FORMAL_MAPPING_OR_OBSERVED_OUTCOME.","round_id":"round-1-blind-review"},'
    b'{"objective":"CRITIQUE_WHETHER_THE_SYNTHETIC_MATRIX_CAN_FALSIFY_EVERY_STATED_INVARIANT.","round_id":"round-2-stress-matrix-critique"},'
    b'{"objective":"PROPOSE_MINIMAL_MECHANICAL_FIXES_AND_STRONGER_REGRESSION_ORACLES_FROM_SYNTHETIC_RESULT_CODES.","round_id":"round-3-results-and-minimal-change"},'
    b'{"objective":"GIVE_FINAL_DISSENT_AND_IDENTIFY_ASSUMPTIONS_THAT_STILL_PREVENT_RELEASE.","round_id":"round-4-final-dissent"}],"schema_version":"qrh-ds-round-objective-spec/v1"}'
)
_ROUND_OBJECTIVE_SPEC_SHA256 = "f77d1572bb7d8c25e94ebe76c79235e3bbfd60a156b793bcc901a3178e368b84"

_SYSTEM_INSTRUCTION = (
    "INDEPENDENT_ARCHITECTURE_VERIFIER. PAYLOAD_PUBLIC_SYNTHETIC_ENUM_ONLY. "
    "RETURN_EXACT_JSON_SCHEMA. FORBID_TOOLS_URLS_PATHS_SENSITIVE_MATERIAL_"
    "PERSONAL_IDENTITIES_EXTERNAL_FACTS_SOURCE_QUOTES. PRINTABLE_ASCII_ONLY. "
    "FINDINGS_ADVISORY_ONLY_NO_RELEASE_AUTHORITY. "
    "FREE_PROSE_USE_UPPERCASE_ENUM_SYMBOLS."
)

_SAFE_FINGERPRINT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLAIM_NONCE = re.compile(r"^claim_[0-9a-f]{32}$")
_SUPERVISOR_NONCE = re.compile(r"^supervisor_[0-9a-f]{64}$")
_FINDING_ID = re.compile(r"^F-[0-9]{3}$")
_DRIVE_RELATIVE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:")
_PATH_SEPARATOR = re.compile(r"[\\/]")
_SECRET_LIKE_PATTERNS = (
    re.compile(r"\bBearer(?:\s+|[:=_-])\S+", re.I),
    re.compile(r"\bsk-[A-Za-z0-9_-]+", re.I),
    re.compile(
        r"(?<![A-Za-z0-9])(?:password|passwd|secret|credential|token|authorization)"
        r"[A-Za-z0-9_-]*",
        re.I,
    ),
    re.compile(r"(?<![A-Za-z0-9])api[ _-]?key(?![A-Za-z0-9])", re.I),
)
_FORBIDDEN_FREE_PROSE = (
    _PATH_SEPARATOR,
    _DRIVE_RELATIVE,
    *_SECRET_LIKE_PATTERNS,
    re.compile(
        r"\b(?:username|"
        r"name|fullname|identity|author|institution|organization|phone|e-?mail)\b",
        re.I,
    ),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"\bcontact\s+[a-z][a-z'-]*(?:\s+[a-z][a-z'-]*)+\b", re.I),
    re.compile(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b"),
    re.compile(r"(?<![A-Za-z])[a-z]\s+[a-z][a-z'-]+(?![A-Za-z])"),
    re.compile(r"(?<![A-Za-z])[a-z][a-z'-]+\s+[a-z][a-z'-]+(?![A-Za-z])"),
    re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
    ),
)

_REQUEST_SLASH_LITERALS = frozenset(
    (DS_REVIEW_DOSSIER_SCHEMA, DS_REVIEW_OUTPUT_SCHEMA)
)


class DSReviewError(RuntimeError):
    """Base fail-closed review error."""


class DossierPolicyError(DSReviewError):
    """A request, manifest, or output violated the synthetic-only contract."""


class CampaignStateError(DSReviewError):
    """A durable campaign transition was not legal or lost its CAS."""


class ExternalReviewDisabled(DSReviewError):
    """Production transport is not present in this reviewed build."""


def _scan_provider_identity_value(value: object, *, label: str) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 256:
        raise DossierPolicyError(f"{label} is outside the fixed text bound")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise DossierPolicyError(f"{label} must be printable ASCII")
    if any(pattern.search(value) for pattern in _SECRET_LIKE_PATTERNS):
        raise DossierPolicyError(f"{label} resembles credential material")
    return value


@dataclass(frozen=True, slots=True)
class ProviderPin:
    host: str
    api_path: str
    model_alias: str
    provider_revision: str
    expected_returned_model: str
    expected_system_fingerprint: str

    @classmethod
    def create(cls, *, expected_system_fingerprint: str) -> "ProviderPin":
        if type(expected_system_fingerprint) is not str or not _SAFE_FINGERPRINT.fullmatch(
            expected_system_fingerprint
        ) or _DRIVE_RELATIVE.search(expected_system_fingerprint):
            raise DossierPolicyError("provider fingerprint is not a safe fixed token")
        _scan_provider_identity_value(
            expected_system_fingerprint, label="provider fingerprint"
        )
        return cls(
            host=DS_REVIEW_API_HOST,
            api_path=DS_REVIEW_API_PATH,
            model_alias=DS_REVIEW_MODEL_ALIAS,
            provider_revision=DS_REVIEW_PROVIDER_REVISION,
            expected_returned_model=DS_REVIEW_MODEL_ALIAS,
            expected_system_fingerprint=expected_system_fingerprint,
        )

    def validate(self) -> None:
        if (
            type(self.host) is not str
            or self.host != DS_REVIEW_API_HOST
            or self.api_path != DS_REVIEW_API_PATH
            or self.model_alias != DS_REVIEW_MODEL_ALIAS
            or self.provider_revision != DS_REVIEW_PROVIDER_REVISION
            or self.expected_returned_model != DS_REVIEW_MODEL_ALIAS
            or type(self.expected_system_fingerprint) is not str
            or not _SAFE_FINGERPRINT.fullmatch(self.expected_system_fingerprint)
            or _DRIVE_RELATIVE.search(self.expected_system_fingerprint)
        ):
            raise DossierPolicyError("provider identity pin is not approved")
        for label, value in asdict(self).items():
            _scan_provider_identity_value(value, label=f"provider pin {label}")


@dataclass(frozen=True, slots=True)
class SyntheticDossier:
    schema_version: str
    dossier_id: str
    observations: tuple[SyntheticObservation, ...]

    def validate(self) -> None:
        canonical_rows = _canonical_scenario_rows()
        if (
            self.schema_version != DS_REVIEW_DOSSIER_SCHEMA
            or self.dossier_id != "PUBLIC_SYNTHETIC_MCP_RAG_DB_V2"
            or type(self.observations) is not tuple
            or len(self.observations) != len(canonical_rows)
            or self.observations != canonical_rows
        ):
            raise DossierPolicyError("synthetic dossier identity or closure is invalid")
        for ordinal, observation in enumerate(self.observations):
            if type(observation) is not SyntheticObservation:
                raise DossierPolicyError("synthetic observation type is invalid")
            observation.validate(ordinal)


@dataclass(frozen=True, slots=True)
class PreparedReview:
    """Deeply immutable outbound request plus immutable binding scalars only."""

    round_id: str
    ordinal: int
    request_bytes: bytes
    request_sha256: str
    dossier_sha256: str
    provider_pin_sha256: str


@dataclass(frozen=True, slots=True)
class CampaignManifest:
    campaign_id: str
    manifest_bytes: bytes
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class PreparedCampaign:
    manifest: CampaignManifest
    rounds: tuple[PreparedReview, ...]


@dataclass(frozen=True, slots=True)
class ClaimedRound:
    campaign_id: str
    manifest_sha256: str
    owner_nonce: str
    review: PreparedReview


def default_synthetic_dossier() -> SyntheticDossier:
    dossier = SyntheticDossier(
        schema_version=DS_REVIEW_DOSSIER_SCHEMA,
        dossier_id="PUBLIC_SYNTHETIC_MCP_RAG_DB_V2",
        observations=_canonical_scenario_rows(),
    )
    dossier.validate()
    return dossier


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(canonical_json(value).encode("utf-8"))


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise DossierPolicyError("JSON contains a duplicate object key")
        value[key] = item
    return value


def _prescan_json_depth(text: str, *, label: str) -> None:
    """Bound nesting before ``json.loads`` can recurse on hostile input."""

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > DS_REVIEW_MAX_JSON_DEPTH:
                raise DossierPolicyError(f"{label} exceeds the JSON depth limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise DossierPolicyError(f"{label} has invalid JSON nesting")


def _strict_json_loads(raw: bytes | str, *, label: str) -> object:
    try:
        text = raw.decode("utf-8") if type(raw) is bytes else raw
        if type(text) is not str:
            raise TypeError
        _prescan_json_depth(text, label=label)
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except DossierPolicyError:
        raise
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise DossierPolicyError(f"{label} is not strict UTF-8 JSON") from None
    _validate_json_tree(value, label=label)
    return value


def _validate_json_tree(value: object, *, label: str, depth: int = 1) -> None:
    if depth > DS_REVIEW_MAX_JSON_DEPTH:
        raise DossierPolicyError(f"{label} exceeds the JSON depth limit")
    if value is None or type(value) in (str, int, float, bool):
        if type(value) is float and (value != value or value in (float("inf"), float("-inf"))):
            raise DossierPolicyError(f"{label} contains a non-finite number")
        return
    if type(value) is list:
        for item in value:
            _validate_json_tree(item, label=label, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise DossierPolicyError(f"{label} contains a non-string key")
            _validate_json_tree(item, label=label, depth=depth + 1)
        return
    raise DossierPolicyError(f"{label} contains an unsupported JSON value")


def _canonical_scenario_rows() -> tuple[SyntheticObservation, ...]:
    raw = _SCENARIO_SPEC_BYTES
    if (
        type(raw) is not bytes
        or hashlib.sha256(raw).hexdigest()
        != "b0ec6268b151a86201ee963de0a783af70df323c9f7d8f670cdfcf8f61e9da51"
    ):
        raise DossierPolicyError("canonical scenario specification hash is invalid")
    value = _strict_json_loads(raw, label="canonical scenario specification")
    if (
        type(value) is not dict
        or set(value) != {"schema_version", "rows"}
        or value["schema_version"] != "qrh-ds-scenario-spec/v1"
        or type(value["rows"]) is not list
        or len(value["rows"]) != 8
        or canonical_json(value).encode("utf-8") != raw
    ):
        raise DossierPolicyError("canonical scenario specification is invalid")
    field_names = {
        "scenario_id",
        "mechanism_id",
        "mechanism",
        "behavior",
        "risk_class",
        "stress_case",
        "invariant_id",
        "invariant",
        "process_count",
        "record_scale",
        "outcome",
    }
    rows: list[SyntheticObservation] = []
    for ordinal, member in enumerate(value["rows"]):
        if (
            type(member) is not dict
            or set(member) != field_names
            or any(
                type(member[field]) is not str
                for field in field_names - {"process_count", "record_scale"}
            )
            or type(member["process_count"]) is not int
            or type(member["record_scale"]) is not int
            or member["process_count"] < 1
            or member["record_scale"] < 1
            or member["scenario_id"] != f"S{ordinal + 1:02d}"
            or member["mechanism_id"] != f"M{ordinal + 1:02d}"
            or member["invariant_id"] != f"I{ordinal + 1:02d}"
            or member["risk_class"]
            not in {"CONCURRENCY", "DURABILITY", "RESOURCE", "CONSISTENCY"}
        ):
            raise DossierPolicyError("canonical scenario row is invalid")
        rows.append(SyntheticObservation(**member))
    return tuple(rows)


def _canonical_round_objective_rows() -> tuple[tuple[str, str], ...]:
    raw = _ROUND_OBJECTIVE_SPEC_BYTES
    if (
        type(raw) is not bytes
        or hashlib.sha256(raw).hexdigest()
        != "f77d1572bb7d8c25e94ebe76c79235e3bbfd60a156b793bcc901a3178e368b84"
    ):
        raise DossierPolicyError("canonical round objective specification hash is invalid")
    value = _strict_json_loads(raw, label="canonical round objective specification")
    if (
        type(value) is not dict
        or set(value) != {"schema_version", "rounds"}
        or value["schema_version"] != "qrh-ds-round-objective-spec/v1"
        or type(value["rounds"]) is not list
        or len(value["rounds"]) != 4
        or canonical_json(value).encode("utf-8") != raw
    ):
        raise DossierPolicyError("canonical round objective specification is invalid")
    rows: list[tuple[str, str]] = []
    for ordinal, member in enumerate(value["rounds"]):
        if (
            type(member) is not dict
            or set(member) != {"round_id", "objective"}
            or type(member["round_id"]) is not str
            or member["round_id"] != (
                "round-1-blind-review",
                "round-2-stress-matrix-critique",
                "round-3-results-and-minimal-change",
                "round-4-final-dissent",
            )[ordinal]
            or type(member["objective"]) is not str
            or not member["objective"]
        ):
            raise DossierPolicyError("canonical round objective row is invalid")
        rows.append((member["round_id"], member["objective"]))
    return tuple(rows)


def _canonical_round_ids() -> tuple[str, ...]:
    return tuple(round_id for round_id, _objective in _canonical_round_objective_rows())


def _canonical_round_objective(round_id: str) -> str:
    rows = dict(_canonical_round_objective_rows())
    if round_id not in rows:
        raise DossierPolicyError("review round is not frozen")
    return rows[round_id]


# Compatibility views only.  Deliberate low-level mutation of either object is
# covered by regression tests and cannot influence a fresh canonical replay.
SCENARIO_ROWS = _canonical_scenario_rows()
_ROUND_OBJECTIVES = dict(_canonical_round_objective_rows())


def _iter_json_strings(value: object) -> Iterable[str]:
    if type(value) is str:
        yield value
    elif type(value) is list:
        for item in value:
            yield from _iter_json_strings(item)
    elif type(value) is dict:
        for key, item in value.items():
            yield key
            yield from _iter_json_strings(item)


def _scan_final_request_bytes(raw: bytes) -> dict[str, object]:
    """Independently scan the final canonical bytes, not their source globals."""

    if type(raw) is not bytes or len(raw) > DS_REVIEW_MAX_REQUEST_BYTES:
        raise DossierPolicyError("final review request size or type is invalid")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise DossierPolicyError("final review request must be ASCII") from None
    value = _strict_json_loads(text, label="final review request policy scan")
    if type(value) is not dict:
        raise DossierPolicyError("final review request must be an object")
    policy_value: object = value
    messages = value.get("messages")
    if (
        type(messages) is list
        and len(messages) == 2
        and type(messages[1]) is dict
        and type(messages[1].get("content")) is str
    ):
        decoded_user = _strict_json_loads(
            messages[1]["content"], label="final review user content policy scan"
        )
        policy_value = {
            **value,
            "messages": [
                messages[0],
                {**messages[1], "content": decoded_user},
            ],
        }
    for item in _iter_json_strings(policy_value):
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in item):
            raise DossierPolicyError("final review request contains non-ASCII text")
        if ("/" in item or "\\" in item) and item not in _REQUEST_SLASH_LITERALS:
            raise DossierPolicyError("final review request contains locator syntax")
        for pattern in _FORBIDDEN_FREE_PROSE:
            if pattern is _PATH_SEPARATOR and item in _REQUEST_SLASH_LITERALS:
                continue
            if pattern.search(item):
                raise DossierPolicyError(
                    "final review request contains forbidden secret, path, or identity syntax"
                )
    return value


def audit_final_request_bytes(raw: bytes) -> str:
    """Re-run final-byte policy and return its canonical request hash."""

    value = _scan_final_request_bytes(raw)
    if canonical_json(value).encode("utf-8") != raw:
        raise DossierPolicyError("final review request is not canonical")
    return _sha256_bytes(raw)


def _scan_free_prose(value: object, *, label: str, max_bytes: int = 1200) -> str:
    if type(value) is not str:
        raise DossierPolicyError(f"{label} must be text")
    encoded = value.encode("utf-8")
    if not value or len(encoded) > max_bytes:
        raise DossierPolicyError(f"{label} length is outside the fixed bound")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise DossierPolicyError(f"{label} must be printable ASCII")
    for pattern in _FORBIDDEN_FREE_PROSE:
        if pattern.search(value):
            raise DossierPolicyError(f"{label} contains forbidden locator or identity syntax")
    return value


def _output_schema() -> dict[str, object]:
    round_ids = _canonical_round_ids()
    mechanism_ids = tuple(row.mechanism_id for row in _canonical_scenario_rows())
    prose = {"type": "string", "minLength": 1, "maxLength": 1200}
    finding = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "finding_id",
            "severity",
            "mechanism_id",
            "rationale",
            "falsification_test",
            "minimal_change",
            "residual_risk",
        ],
        "properties": {
            "finding_id": {"type": "string", "pattern": "^F-[0-9]{3}$"},
            "severity": {"type": "string", "enum": ["blocker", "high", "medium", "low"]},
            "mechanism_id": {"type": "string", "enum": list(mechanism_ids)},
            "rationale": prose,
            "falsification_test": prose,
            "minimal_change": prose,
            "residual_risk": prose,
        },
    }
    prose_list = {
        "type": "array",
        "minItems": 1,
        "maxItems": 12,
        "items": prose,
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "round_id", "release_position", "findings", "dissent"],
        "properties": {
            "schema_version": {"const": DS_REVIEW_OUTPUT_SCHEMA},
            "round_id": {"type": "string", "enum": list(round_ids)},
            "release_position": {"type": "string", "enum": ["block", "conditional", "proceed"]},
            "findings": {"type": "array", "minItems": 1, "maxItems": 24, "items": finding},
            "dissent": {
                "type": "object",
                "additionalProperties": False,
                "required": ["why_not_release", "missing_stress_cases", "assumptions_to_break"],
                "properties": {
                    "why_not_release": prose_list,
                    "missing_stress_cases": prose_list,
                    "assumptions_to_break": prose_list,
                },
            },
        },
    }


def _scenario_projection(*, include_mapping: bool, include_outcome: bool) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for source in _canonical_scenario_rows():
        if include_mapping:
            row = asdict(source)
        else:
            row = {
                "scenario_id": source.scenario_id,
                "mechanism_id": source.mechanism_id,
                "invariant_id": source.invariant_id,
                "behavior": source.behavior,
                "risk_class": source.risk_class,
            }
        if not include_outcome:
            row.pop("outcome", None)
        rows.append(row)
    return rows


def _user_payload(round_id: str) -> dict[str, object]:
    round_ids = _canonical_round_ids()
    scenario_rows = _canonical_scenario_rows()
    if round_id not in round_ids:
        raise DossierPolicyError("review round is not frozen")
    value: dict[str, object] = {
        "contract": {
            "dossier_schema": DS_REVIEW_DOSSIER_SCHEMA,
            "output_schema": _output_schema(),
            "provider_revision": DS_REVIEW_PROVIDER_REVISION,
            "round_id": round_id,
            "objective": _canonical_round_objective(round_id),
            "authority": "ADVISORY_ONLY",
        },
    }
    if round_id == round_ids[0]:
        value["anonymous_architecture"] = _scenario_projection(
            include_mapping=False, include_outcome=False
        )
    else:
        value["architecture_mapping"] = [
            {
                "mechanism_id": row.mechanism_id,
                "mechanism": row.mechanism,
                "invariant_id": row.invariant_id,
                "invariant": row.invariant,
            }
            for row in scenario_rows
        ]
        value["stress_matrix"] = _scenario_projection(
            include_mapping=True, include_outcome=False
        )
    if round_id in (round_ids[2], round_ids[3]):
        value["synthetic_observations"] = _scenario_projection(
            include_mapping=True, include_outcome=True
        )
    return value


def _request_bytes(round_id: str) -> bytes:
    value = {
        "model": DS_REVIEW_MODEL_ALIAS,
        "messages": [
            {"role": "system", "content": _SYSTEM_INSTRUCTION},
            {"role": "user", "content": canonical_json(_user_payload(round_id))},
        ],
        "response_format": {"type": "json_object"},
        "stream": False,
    }
    raw = canonical_json(value).encode("utf-8")
    if len(raw) > DS_REVIEW_MAX_REQUEST_BYTES:
        raise DossierPolicyError("canonical review request exceeds the fixed cap")
    audit_final_request_bytes(raw)
    return raw


def _provider_pin_projection(pin: ProviderPin) -> dict[str, str]:
    pin.validate()
    return asdict(pin)


def _request_hash_after_rescan(raw: bytes) -> str:
    return audit_final_request_bytes(raw)


def prepare_campaign(dossier: SyntheticDossier, *, pin: ProviderPin) -> PreparedCampaign:
    """Freeze four canonical requests and bind them to one independent manifest."""

    campaign = _prepare_campaign_unchecked(dossier, pin=pin)
    validate_campaign(campaign)
    return campaign


def _decode_manifest(manifest: CampaignManifest) -> dict[str, object]:
    if (
        type(manifest.campaign_id) is not str
        or type(manifest.manifest_bytes) is not bytes
        or type(manifest.manifest_sha256) is not str
        or not _SHA256.fullmatch(manifest.manifest_sha256)
        or _sha256_bytes(manifest.manifest_bytes) != manifest.manifest_sha256
    ):
        raise DossierPolicyError("campaign manifest scalar binding is invalid")
    value = _strict_json_loads(manifest.manifest_bytes, label="campaign manifest")
    if type(value) is not dict or canonical_json(value).encode("utf-8") != manifest.manifest_bytes:
        raise DossierPolicyError("campaign manifest is not canonical")
    expected_keys = {
        "campaign_id",
        "schema_version",
        "provider_pin",
        "provider_pin_sha256",
        "dossier_sha256",
        "round_order",
        "rounds",
        "scenario_mapping",
        "overall_deadline_seconds",
        "external_transport_state",
        "authority",
    }
    if set(value) != expected_keys or value.get("campaign_id") != manifest.campaign_id:
        raise DossierPolicyError("campaign manifest top-level contract is invalid")
    return value


def validate_campaign(campaign: PreparedCampaign) -> None:
    if type(campaign) is not PreparedCampaign or type(campaign.rounds) is not tuple:
        raise DossierPolicyError("prepared campaign type is invalid")
    value = _decode_manifest(campaign.manifest)
    if (
        value["schema_version"] != DS_REVIEW_MANIFEST_SCHEMA
        or value["round_order"] != list(_canonical_round_ids())
        or value["scenario_mapping"]
        != [asdict(row) for row in _canonical_scenario_rows()]
        or type(value["overall_deadline_seconds"]) is not float
        or value["overall_deadline_seconds"] != DS_REVIEW_OVERALL_DEADLINE_SECONDS
        or value["external_transport_state"] != EXTERNAL_TRANSPORT_STATE
        or value["authority"] != "ADVISORY_ONLY"
        or len(campaign.rounds) != 4
    ):
        raise DossierPolicyError("campaign manifest frozen contract is invalid")
    pin_raw = value["provider_pin"]
    if type(pin_raw) is not dict:
        raise DossierPolicyError("campaign provider pin is invalid")
    try:
        pin = ProviderPin(**pin_raw)
    except TypeError:
        raise DossierPolicyError("campaign provider pin fields are invalid") from None
    pin.validate()
    if value["provider_pin_sha256"] != _sha256_json(pin_raw):
        raise DossierPolicyError("campaign provider pin hash is invalid")
    dossier = default_synthetic_dossier()
    expected = _prepare_campaign_unchecked(dossier, pin=pin)
    if (
        expected.manifest.manifest_bytes != campaign.manifest.manifest_bytes
        or expected.rounds != campaign.rounds
    ):
        raise DossierPolicyError("campaign does not match the frozen canonical construction")


def _prepare_campaign_unchecked(dossier: SyntheticDossier, *, pin: ProviderPin) -> PreparedCampaign:
    """Internal constructor used to avoid recursion during validation."""

    dossier.validate()
    pin_projection = _provider_pin_projection(pin)
    dossier_projection = {
        "schema_version": dossier.schema_version,
        "dossier_id": dossier.dossier_id,
        "observations": [asdict(row) for row in dossier.observations],
    }
    dossier_sha256 = _sha256_json(dossier_projection)
    provider_pin_sha256 = _sha256_json(pin_projection)
    rounds = tuple(
        PreparedReview(
            round_id=round_id,
            ordinal=ordinal,
            request_bytes=(raw := _request_bytes(round_id)),
            request_sha256=_request_hash_after_rescan(raw),
            dossier_sha256=dossier_sha256,
            provider_pin_sha256=provider_pin_sha256,
        )
        for ordinal, round_id in enumerate(_canonical_round_ids())
    )
    core = {
        "schema_version": DS_REVIEW_MANIFEST_SCHEMA,
        "provider_pin": pin_projection,
        "provider_pin_sha256": provider_pin_sha256,
        "dossier_sha256": dossier_sha256,
        "round_order": list(_canonical_round_ids()),
        "rounds": [
            {"ordinal": row.ordinal, "round_id": row.round_id, "request_sha256": row.request_sha256}
            for row in rounds
        ],
        "scenario_mapping": [asdict(row) for row in _canonical_scenario_rows()],
        "overall_deadline_seconds": DS_REVIEW_OVERALL_DEADLINE_SECONDS,
        "external_transport_state": EXTERNAL_TRANSPORT_STATE,
        "authority": "ADVISORY_ONLY",
    }
    campaign_id = "dscamp_" + _sha256_json(core)[:32]
    raw = canonical_json({"campaign_id": campaign_id, **core}).encode("utf-8")
    return PreparedCampaign(
        manifest=CampaignManifest(campaign_id, raw, _sha256_bytes(raw)),
        rounds=rounds,
    )


def _decode_review(review: PreparedReview) -> dict[str, object]:
    round_ids = _canonical_round_ids()
    if (
        type(review.round_id) is not str
        or review.round_id not in round_ids
        or type(review.ordinal) is not int
        or review.ordinal != round_ids.index(review.round_id)
        or type(review.request_bytes) is not bytes
        or len(review.request_bytes) > DS_REVIEW_MAX_REQUEST_BYTES
        or type(review.request_sha256) is not str
        or not _SHA256.fullmatch(review.request_sha256)
        or _sha256_bytes(review.request_bytes) != review.request_sha256
        or type(review.dossier_sha256) is not str
        or not _SHA256.fullmatch(review.dossier_sha256)
        or type(review.provider_pin_sha256) is not str
        or not _SHA256.fullmatch(review.provider_pin_sha256)
    ):
        raise DossierPolicyError("prepared review immutable binding is invalid")
    # The final bytes are independently decoded and policy-scanned on every
    # prepared-use boundary; equality with module globals is an additional gate.
    if audit_final_request_bytes(review.request_bytes) != review.request_sha256:
        raise DossierPolicyError("prepared review policy hash is invalid")
    value = _scan_final_request_bytes(review.request_bytes)
    if type(value) is not dict or canonical_json(value).encode("utf-8") != review.request_bytes:
        raise DossierPolicyError("prepared request is not canonical")
    if set(value) != {"model", "messages", "response_format", "stream"}:
        raise DossierPolicyError("prepared request top-level contract is invalid")
    if (
        value["model"] != DS_REVIEW_MODEL_ALIAS
        or value["response_format"] != {"type": "json_object"}
        or type(value["stream"]) is not bool
        or value["stream"] is not False
        or type(value["messages"]) is not list
        or len(value["messages"]) != 2
    ):
        raise DossierPolicyError("prepared request transport contract is invalid")
    system, user = value["messages"]
    if (
        type(system) is not dict
        or set(system) != {"role", "content"}
        or system != {"role": "system", "content": _SYSTEM_INSTRUCTION}
        or type(user) is not dict
        or set(user) != {"role", "content"}
        or user.get("role") != "user"
        or type(user.get("content")) is not str
    ):
        raise DossierPolicyError("prepared request message contract is invalid")
    user_payload = _strict_json_loads(user["content"], label="prepared user payload")
    if (
        type(user_payload) is not dict
        or canonical_json(user_payload) != user["content"]
        or user_payload != _user_payload(review.round_id)
    ):
        raise DossierPolicyError("prepared synthetic payload is not the frozen allowlist value")
    return value


def validate_review_output(value: object, *, round_id: str) -> dict[str, object]:
    _validate_json_tree(value, label="review output")
    if type(value) is not dict or set(value) != {
        "schema_version",
        "round_id",
        "release_position",
        "findings",
        "dissent",
    }:
        raise DossierPolicyError("review output top-level contract is invalid")
    if value["schema_version"] != DS_REVIEW_OUTPUT_SCHEMA or value["round_id"] != round_id:
        raise DossierPolicyError("review output identity is invalid")
    if value["release_position"] not in ("block", "conditional", "proceed"):
        raise DossierPolicyError("review release position is invalid")
    findings = value["findings"]
    if type(findings) is not list or not 1 <= len(findings) <= 24:
        raise DossierPolicyError("review findings count is invalid")
    finding_keys = {
        "finding_id",
        "severity",
        "mechanism_id",
        "rationale",
        "falsification_test",
        "minimal_change",
        "residual_risk",
    }
    seen: set[str] = set()
    for finding in findings:
        if type(finding) is not dict or set(finding) != finding_keys:
            raise DossierPolicyError("review finding contract is invalid")
        finding_id = finding["finding_id"]
        if type(finding_id) is not str or not _FINDING_ID.fullmatch(finding_id) or finding_id in seen:
            raise DossierPolicyError("review finding id is invalid")
        seen.add(finding_id)
        if finding["severity"] not in ("blocker", "high", "medium", "low"):
            raise DossierPolicyError("review finding severity is invalid")
        if finding["mechanism_id"] not in {
            row.mechanism_id for row in _canonical_scenario_rows()
        }:
            raise DossierPolicyError("review finding mechanism id is invalid")
        for key in ("rationale", "falsification_test", "minimal_change", "residual_risk"):
            _scan_free_prose(finding[key], label=f"review finding {key}")
    dissent = value["dissent"]
    dissent_keys = {"why_not_release", "missing_stress_cases", "assumptions_to_break"}
    if type(dissent) is not dict or set(dissent) != dissent_keys:
        raise DossierPolicyError("review dissent contract is invalid")
    for key in sorted(dissent_keys):
        rows = dissent[key]
        if type(rows) is not list or not 1 <= len(rows) <= 12:
            raise DossierPolicyError("review dissent count is invalid")
        for row in rows:
            _scan_free_prose(row, label=f"review dissent {key}")
    return value


def _campaign_pin(campaign: PreparedCampaign) -> ProviderPin:
    raw = _decode_manifest(campaign.manifest)
    pin_raw = raw["provider_pin"]
    if type(pin_raw) is not dict:
        raise DossierPolicyError("campaign provider pin is invalid")
    try:
        pin = ProviderPin(**pin_raw)
    except TypeError:
        raise DossierPolicyError("campaign provider pin fields are invalid") from None
    pin.validate()
    return pin


def _bound_review(campaign: PreparedCampaign, round_id: str) -> PreparedReview:
    validate_campaign(campaign)
    round_ids = _canonical_round_ids()
    if round_id not in round_ids:
        raise DossierPolicyError("campaign round id is invalid")
    review = campaign.rounds[round_ids.index(round_id)]
    _decode_review(review)
    manifest = _decode_manifest(campaign.manifest)
    expected_row = manifest["rounds"][review.ordinal]
    if expected_row != {
        "ordinal": review.ordinal,
        "round_id": review.round_id,
        "request_sha256": review.request_sha256,
    }:
        raise DossierPolicyError("review is not bound to the campaign manifest")
    if (
        review.dossier_sha256 != manifest["dossier_sha256"]
        or review.provider_pin_sha256 != manifest["provider_pin_sha256"]
    ):
        raise DossierPolicyError("review campaign hash binding is invalid")
    return review


def dry_run_receipt(campaign: PreparedCampaign, *, round_id: str) -> dict[str, object]:
    review = _bound_review(campaign, round_id)
    # Re-decode and re-scan immediately before producing the receipt.
    _decode_review(review)
    return {
        "schema_version": DS_REVIEW_RECEIPT_SCHEMA,
        "status": "dry_run_no_network",
        "campaign_id": campaign.manifest.campaign_id,
        "campaign_manifest_sha256": campaign.manifest.manifest_sha256,
        "round_id": round_id,
        "ordinal": review.ordinal,
        "request_sha256": review.request_sha256,
        "request_bytes": len(review.request_bytes),
        "authority": "ADVISORY_ONLY",
        "external_transport_state": EXTERNAL_TRANSPORT_STATE,
        "network_calls": 0,
    }


def parse_provider_response(
    raw: bytes,
    *,
    campaign: PreparedCampaign,
    round_id: str,
    elapsed_seconds: float,
) -> dict[str, object]:
    """Credential-free strict parser used by fake tests and a future isolated child."""

    review = _bound_review(campaign, round_id)
    _decode_review(review)
    if (
        type(raw) is not bytes
        or len(raw) > DS_REVIEW_MAX_RESPONSE_BYTES
        or type(elapsed_seconds) is not float
        or elapsed_seconds < 0.0
        or elapsed_seconds > DS_REVIEW_OVERALL_DEADLINE_SECONDS
    ):
        raise DossierPolicyError("review response exceeded a fixed type, size, or deadline bound")
    outer = _strict_json_loads(raw, label="provider response")
    if type(outer) is not dict or set(outer) != {
        "id",
        "created",
        "model",
        "system_fingerprint",
        "choices",
    }:
        raise DossierPolicyError("provider response top-level contract is invalid")
    if (
        type(outer["id"]) is not str
        or not outer["id"]
        or type(outer["created"]) is not int
        or type(outer["model"]) is not str
        or type(outer["system_fingerprint"]) is not str
        or type(outer["choices"]) is not list
        or len(outer["choices"]) != 1
    ):
        raise DossierPolicyError("provider response scalar contract is invalid")
    _scan_free_prose(
        outer["id"], label="provider response id", max_bytes=256
    )
    pin = _campaign_pin(campaign)
    if (
        outer["model"] != pin.expected_returned_model
        or outer["system_fingerprint"] != pin.expected_system_fingerprint
    ):
        raise DossierPolicyError("provider response identity drifted")
    choice = outer["choices"][0]
    if (
        type(choice) is not dict
        or set(choice) != {"index", "message", "finish_reason"}
        or type(choice["index"]) is not int
        or choice["index"] != 0
        or choice["finish_reason"] != "stop"
        or type(choice["message"]) is not dict
        or set(choice["message"]) != {"role", "content"}
        or choice["message"]["role"] != "assistant"
        or type(choice["message"]["content"]) is not str
    ):
        raise DossierPolicyError("provider response choice contract is invalid")
    output = _strict_json_loads(choice["message"]["content"], label="review output")
    validated = validate_review_output(output, round_id=round_id)
    try:
        created_at = datetime.fromtimestamp(outer["created"], tz=UTC).isoformat().replace(
            "+00:00", "Z"
        )
    except (OverflowError, OSError, ValueError):
        raise DossierPolicyError("provider response timestamp is invalid") from None
    output_bytes = canonical_json(validated).encode("utf-8")
    return {
        "schema_version": DS_REVIEW_RECEIPT_SCHEMA,
        "status": "advisory_parsed_without_transport",
        "campaign_id": campaign.manifest.campaign_id,
        "campaign_manifest_sha256": campaign.manifest.manifest_sha256,
        "round_id": round_id,
        "ordinal": review.ordinal,
        "response_id_sha256": _sha256_bytes(outer["id"].encode("utf-8")),
        "created_at": created_at,
        "provider_revision": pin.provider_revision,
        "returned_model": outer["model"],
        "system_fingerprint_sha256": _sha256_bytes(
            outer["system_fingerprint"].encode("utf-8")
        ),
        "request_sha256": review.request_sha256,
        "output_sha256": _sha256_bytes(output_bytes),
        "redacted_output": validated,
        "elapsed_seconds": elapsed_seconds,
        "authority": "ADVISORY_ONLY",
        "network_calls_by_parser": 0,
    }


def external_review(*_args: object, **_kwargs: object) -> None:
    """Unconditionally unreachable until a later independently reviewed build."""

    raise ExternalReviewDisabled("external architecture review transport is not present")


def new_claim_nonce() -> str:
    return "claim_" + secrets.token_hex(16)


def new_supervisor_nonce() -> str:
    return "supervisor_" + secrets.token_hex(32)


def _supervisor_nonce_sha256(value: str) -> str:
    if type(value) is not str or not _SUPERVISOR_NONCE.fullmatch(value):
        raise CampaignStateError("supervisor recovery binding is invalid")
    return _sha256_bytes(value.encode("ascii"))


class CampaignLedger:
    """Durable four-round CAS ledger; only synthetic simulation claims are enabled."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("campaign ledger path must be a Path")
        ensure_no_reparse_components(path.parent)
        parent = path.parent.resolve(strict=True)
        if not parent.is_dir():
            raise CampaignStateError("campaign ledger parent is unavailable")
        self.path = parent / path.name
        if self.path.exists():
            ensure_no_reparse_components(self.path)
            info = self.path.lstat()
            if stat_is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise CampaignStateError("campaign ledger file is unsafe")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    manifest_sha256 TEXT NOT NULL UNIQUE,
                    manifest_bytes BLOB NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('PREREGISTERED','SIMULATION_APPROVED','COMPLETE')),
                    approval_evidence_sha256 TEXT,
                    schema_version TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS owner_envelopes (
                    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
                    owner_nonce TEXT NOT NULL,
                    supervisor_nonce_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('PREPARED','BOUND','CONSUMED')),
                    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 3),
                    PRIMARY KEY (campaign_id, owner_nonce),
                    UNIQUE (campaign_id, supervisor_nonce_sha256)
                );
                CREATE TABLE IF NOT EXISTS rounds (
                    campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
                    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 3),
                    round_id TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('PREREGISTERED','CLAIMED','CONSUMED')),
                    owner_nonce TEXT,
                    outcome TEXT CHECK (outcome IN ('SUCCEEDED','FAILED') OR outcome IS NULL),
                    receipt_sha256 TEXT,
                    PRIMARY KEY (campaign_id, ordinal),
                    UNIQUE (campaign_id, round_id),
                    UNIQUE (campaign_id, request_sha256)
                );
                CREATE TABLE IF NOT EXISTS consumed_ledger (
                    campaign_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    round_id TEXT NOT NULL,
                    owner_nonce TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK (outcome IN ('SUCCEEDED','FAILED')),
                    receipt_sha256 TEXT NOT NULL,
                    PRIMARY KEY (campaign_id, ordinal),
                    FOREIGN KEY (campaign_id, ordinal) REFERENCES rounds(campaign_id, ordinal)
                );
                """
            )
        finally:
            connection.close()

    def install(self, campaign: PreparedCampaign) -> None:
        validate_campaign(campaign)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO campaigns VALUES (?,?,?,?,?,?)",
                (
                    campaign.manifest.campaign_id,
                    campaign.manifest.manifest_sha256,
                    campaign.manifest.manifest_bytes,
                    "PREREGISTERED",
                    None,
                    DS_REVIEW_LEDGER_SCHEMA,
                ),
            )
            connection.executemany(
                "INSERT INTO rounds VALUES (?,?,?,?,?,?,?,?)",
                [
                    (
                        campaign.manifest.campaign_id,
                        row.ordinal,
                        row.round_id,
                        row.request_sha256,
                        "PREREGISTERED",
                        None,
                        None,
                        None,
                    )
                    for row in campaign.rounds
                ],
            )
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            raise CampaignStateError("campaign is already installed or conflicts") from None
        finally:
            connection.close()

    def approve_simulation(
        self,
        campaign_id: str,
        *,
        manifest_sha256: str,
        approval_evidence_sha256: str,
    ) -> None:
        if (
            type(manifest_sha256) is not str
            or not _SHA256.fullmatch(manifest_sha256)
            or type(approval_evidence_sha256) is not str
            or not _SHA256.fullmatch(approval_evidence_sha256)
        ):
            raise CampaignStateError("campaign approval hashes are invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE campaigns
                   SET state='SIMULATION_APPROVED', approval_evidence_sha256=?
                 WHERE campaign_id=? AND manifest_sha256=? AND state='PREREGISTERED'
                """,
                (approval_evidence_sha256, campaign_id, manifest_sha256),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise CampaignStateError("campaign simulation approval CAS failed")
            connection.commit()
        finally:
            connection.close()

    def approve_external(self, *_args: object, **_kwargs: object) -> None:
        raise ExternalReviewDisabled("external campaign approval is disabled in this build")

    def persist_owner_envelope(
        self,
        campaign_id: str,
        *,
        manifest_sha256: str,
        owner_nonce: str,
        supervisor_nonce: str,
        intended_ordinal: int,
    ) -> None:
        """Persist recovery material before a process may compete for a claim."""

        if (
            type(manifest_sha256) is not str
            or not _SHA256.fullmatch(manifest_sha256)
            or type(owner_nonce) is not str
            or not _CLAIM_NONCE.fullmatch(owner_nonce)
            or type(intended_ordinal) is not int
            or not 0 <= intended_ordinal < len(_canonical_round_ids())
        ):
            raise CampaignStateError("owner envelope binding is invalid")
        supervisor_hash = _supervisor_nonce_sha256(supervisor_nonce)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            campaign = connection.execute(
                "SELECT state, manifest_sha256 FROM campaigns WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            if (
                campaign is None
                or campaign["state"] != "SIMULATION_APPROVED"
                or campaign["manifest_sha256"] != manifest_sha256
            ):
                raise CampaignStateError("owner envelope campaign binding failed")
            connection.execute(
                "INSERT INTO owner_envelopes VALUES (?,?,?,?,?)",
                (
                    campaign_id,
                    owner_nonce,
                    supervisor_hash,
                    "PREPARED",
                    intended_ordinal,
                ),
            )
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            raise CampaignStateError("owner or supervisor envelope is already registered") from None
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _load_campaign(self, connection: sqlite3.Connection, campaign_id: str) -> PreparedCampaign:
        row = connection.execute(
            "SELECT manifest_bytes, manifest_sha256 FROM campaigns WHERE campaign_id=?",
            (campaign_id,),
        ).fetchone()
        if row is None or type(row["manifest_bytes"]) is not bytes:
            raise CampaignStateError("campaign manifest is unavailable")
        manifest = CampaignManifest(campaign_id, row["manifest_bytes"], row["manifest_sha256"])
        raw = _decode_manifest(manifest)
        pin_raw = raw["provider_pin"]
        if type(pin_raw) is not dict:
            raise CampaignStateError("campaign provider pin is invalid")
        campaign = prepare_campaign(default_synthetic_dossier(), pin=ProviderPin(**pin_raw))
        if campaign.manifest != manifest:
            raise CampaignStateError("durable campaign manifest failed canonical replay")
        return campaign

    def claim_next(
        self,
        campaign_id: str,
        *,
        manifest_sha256: str,
        owner_nonce: str,
        mode: str = "SIMULATION",
    ) -> ClaimedRound:
        if mode != "SIMULATION":
            raise ExternalReviewDisabled("only credential-free simulation claims are enabled")
        if (
            type(manifest_sha256) is not str
            or not _SHA256.fullmatch(manifest_sha256)
            or type(owner_nonce) is not str
            or not _CLAIM_NONCE.fullmatch(owner_nonce)
        ):
            raise CampaignStateError("campaign claim binding is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            campaign_row = connection.execute(
                "SELECT state, manifest_sha256 FROM campaigns WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            if (
                campaign_row is None
                or campaign_row["state"] != "SIMULATION_APPROVED"
                or campaign_row["manifest_sha256"] != manifest_sha256
            ):
                raise CampaignStateError("campaign is not approved for this exact manifest")
            envelope = connection.execute(
                """
                SELECT state, ordinal FROM owner_envelopes
                 WHERE campaign_id=? AND owner_nonce=?
                """,
                (campaign_id, owner_nonce),
            ).fetchone()
            if envelope is None or envelope["state"] != "PREPARED":
                raise CampaignStateError("a prepared owner envelope is required before claim")
            row = connection.execute(
                """
                SELECT ordinal, round_id, state
                  FROM rounds
                 WHERE campaign_id=? AND state!='CONSUMED'
                 ORDER BY ordinal LIMIT 1
                """,
                (campaign_id,),
            ).fetchone()
            if row is None:
                raise CampaignStateError("campaign has no unconsumed round")
            if row["state"] != "PREREGISTERED":
                raise CampaignStateError("next campaign round is already claimed")
            if envelope["ordinal"] != row["ordinal"]:
                raise CampaignStateError("owner envelope is frozen for a different round")
            cursor = connection.execute(
                """
                UPDATE rounds SET state='CLAIMED', owner_nonce=?
                 WHERE campaign_id=? AND ordinal=? AND state='PREREGISTERED'
                """,
                (owner_nonce, campaign_id, row["ordinal"]),
            )
            if cursor.rowcount != 1:
                raise CampaignStateError("campaign round claim CAS failed")
            envelope_cursor = connection.execute(
                """
                UPDATE owner_envelopes SET state='BOUND'
                 WHERE campaign_id=? AND owner_nonce=? AND state='PREPARED'
                """,
                (campaign_id, owner_nonce),
            )
            if envelope_cursor.rowcount != 1:
                raise CampaignStateError("owner envelope bind CAS failed")
            campaign = self._load_campaign(connection, campaign_id)
            candidate = campaign.rounds[row["ordinal"]]
            review = _bound_review(campaign, candidate.round_id)
            connection.commit()
            return ClaimedRound(campaign_id, manifest_sha256, owner_nonce, review)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def recover_claim(
        self,
        campaign_id: str,
        *,
        manifest_sha256: str,
        supervisor_nonce: str,
    ) -> ClaimedRound:
        """Reconstruct the same committed claim; never creates or steals one."""

        if (
            type(manifest_sha256) is not str
            or not _SHA256.fullmatch(manifest_sha256)
        ):
            raise CampaignStateError("claim replay manifest binding is invalid")
        supervisor_hash = _supervisor_nonce_sha256(supervisor_nonce)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            campaign_row = connection.execute(
                "SELECT state, manifest_sha256 FROM campaigns WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            if (
                campaign_row is None
                or campaign_row["state"] != "SIMULATION_APPROVED"
                or campaign_row["manifest_sha256"] != manifest_sha256
            ):
                raise CampaignStateError("claim recovery campaign binding failed")
            envelope = connection.execute(
                """
                SELECT owner_nonce, ordinal, state
                  FROM owner_envelopes
                 WHERE campaign_id=? AND supervisor_nonce_sha256=?
                """,
                (campaign_id, supervisor_hash),
            ).fetchone()
            if (
                envelope is None
                or envelope["state"] != "BOUND"
                or type(envelope["ordinal"]) is not int
            ):
                raise CampaignStateError("supervisor has no recoverable committed claim")
            round_row = connection.execute(
                """
                SELECT round_id, state, owner_nonce
                  FROM rounds
                 WHERE campaign_id=? AND ordinal=?
                """,
                (campaign_id, envelope["ordinal"]),
            ).fetchone()
            if (
                round_row is None
                or round_row["state"] != "CLAIMED"
                or round_row["owner_nonce"] != envelope["owner_nonce"]
            ):
                raise CampaignStateError("owner envelope does not match a live claim")
            campaign = self._load_campaign(connection, campaign_id)
            candidate = campaign.rounds[envelope["ordinal"]]
            review = _bound_review(campaign, candidate.round_id)
            connection.commit()
            return ClaimedRound(
                campaign_id,
                manifest_sha256,
                envelope["owner_nonce"],
                review,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def consume(
        self,
        claim: ClaimedRound,
        *,
        outcome: str,
        receipt_sha256: str,
    ) -> None:
        if (
            type(claim) is not ClaimedRound
            or type(claim.campaign_id) is not str
            or not claim.campaign_id
            or type(claim.review) is not PreparedReview
            or type(outcome) is not str
            or outcome not in ("SUCCEEDED", "FAILED")
            or type(receipt_sha256) is not str
            or not _SHA256.fullmatch(receipt_sha256)
            or type(claim.manifest_sha256) is not str
            or not _SHA256.fullmatch(claim.manifest_sha256)
            or type(claim.owner_nonce) is not str
            or not _CLAIM_NONCE.fullmatch(claim.owner_nonce)
        ):
            raise CampaignStateError("campaign consumption outcome is invalid")
        _decode_review(claim.review)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            campaign = self._load_campaign(connection, claim.campaign_id)
            if (
                campaign.manifest.campaign_id != claim.campaign_id
                or campaign.manifest.manifest_sha256 != claim.manifest_sha256
            ):
                raise CampaignStateError("campaign consumption manifest binding failed")
            expected_review = _bound_review(campaign, claim.review.round_id)
            if claim.review != expected_review:
                raise CampaignStateError(
                    "campaign consumption review binding failed"
                )
            cursor = connection.execute(
                """
                UPDATE rounds
                   SET state='CONSUMED', outcome=?, receipt_sha256=?
                 WHERE campaign_id=? AND ordinal=? AND round_id=?
                   AND state='CLAIMED' AND owner_nonce=? AND request_sha256=?
                """,
                (
                    outcome,
                    receipt_sha256,
                    claim.campaign_id,
                    expected_review.ordinal,
                    expected_review.round_id,
                    claim.owner_nonce,
                    expected_review.request_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise CampaignStateError("campaign consumption CAS failed")
            connection.execute(
                "INSERT INTO consumed_ledger VALUES (?,?,?,?,?,?)",
                (
                    claim.campaign_id,
                    expected_review.ordinal,
                    expected_review.round_id,
                    claim.owner_nonce,
                    outcome,
                    receipt_sha256,
                ),
            )
            envelope_cursor = connection.execute(
                """
                UPDATE owner_envelopes SET state='CONSUMED'
                 WHERE campaign_id=? AND owner_nonce=? AND ordinal=? AND state='BOUND'
                """,
                (
                    claim.campaign_id,
                    claim.owner_nonce,
                    expected_review.ordinal,
                ),
            )
            if envelope_cursor.rowcount != 1:
                raise CampaignStateError("owner envelope consumption CAS failed")
            remaining = connection.execute(
                "SELECT COUNT(*) FROM rounds WHERE campaign_id=? AND state!='CONSUMED'",
                (claim.campaign_id,),
            ).fetchone()[0]
            if remaining == 0:
                connection.execute(
                    "UPDATE campaigns SET state='COMPLETE' WHERE campaign_id=?",
                    (claim.campaign_id,),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def snapshot(self, campaign_id: str) -> dict[str, object]:
        connection = self._connect()
        try:
            campaign = connection.execute(
                "SELECT state, manifest_sha256, approval_evidence_sha256 FROM campaigns WHERE campaign_id=?",
                (campaign_id,),
            ).fetchone()
            if campaign is None:
                raise CampaignStateError("campaign is unavailable")
            rounds = connection.execute(
                "SELECT ordinal, round_id, request_sha256, state, outcome, receipt_sha256 FROM rounds WHERE campaign_id=? ORDER BY ordinal",
                (campaign_id,),
            ).fetchall()
        finally:
            connection.close()
        return {
            "schema_version": DS_REVIEW_LEDGER_SCHEMA,
            "campaign_id": campaign_id,
            "state": campaign["state"],
            "manifest_sha256": campaign["manifest_sha256"],
            "approval_evidence_sha256": campaign["approval_evidence_sha256"],
            "rounds": [dict(row) for row in rounds],
            "external_transport_state": EXTERNAL_TRANSPORT_STATE,
        }


__all__ = [
    "CampaignLedger",
    "CampaignManifest",
    "CampaignStateError",
    "ClaimedRound",
    "DS_REVIEW_API_HOST",
    "DS_REVIEW_API_PATH",
    "DS_REVIEW_MAX_JSON_DEPTH",
    "DS_REVIEW_MODEL_ALIAS",
    "DS_REVIEW_OVERALL_DEADLINE_SECONDS",
    "DS_REVIEW_PROVIDER_REVISION",
    "DSReviewError",
    "DossierPolicyError",
    "EXTERNAL_TRANSPORT_STATE",
    "ExternalReviewDisabled",
    "MECHANISM_IDS",
    "MECHANISMS",
    "PreparedCampaign",
    "PreparedReview",
    "ProviderPin",
    "ROUND_IDS",
    "SCENARIO_ROWS",
    "SyntheticDossier",
    "SyntheticObservation",
    "audit_final_request_bytes",
    "default_synthetic_dossier",
    "dry_run_receipt",
    "external_review",
    "new_claim_nonce",
    "new_supervisor_nonce",
    "parse_provider_response",
    "prepare_campaign",
    "validate_campaign",
    "validate_review_output",
]
