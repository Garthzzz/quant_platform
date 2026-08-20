"""Default-publishable reference policy with explicit quarantine boundaries."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
from pathlib import PurePosixPath
import re
from typing import Literal


POLICY_VERSION = "qrh-reference-source-policy/v1"

_RESERVED_DIRECTORIES = frozenset(
    {"旧版原始文件", "experiments", "experiment", "legacy", "internal", "private"}
)
_RESERVED_NAME_RE = re.compile(
    r"(?:^|[._-])(draft|tmp|temp|backup|bak|private)(?:[._-]|$)", re.IGNORECASE
)
_SUPPORTING_NAMES = frozenset(
    {"readme.md", "glossary.md", "progress_log.md", "changelog.md"}
)

# Patterns are intentionally high confidence.  A hit quarantines the source and
# the scanner reports only the rule name, never the matching value.
_SECRET_RULES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private_key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github_token", re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    (
        "credential_assignment",
        re.compile(
            rb"(?i)(?:api[_-]?key|secret|password)\s*[:=]\s*['\"][A-Za-z0-9_./+\-=]{20,}['\"]"
        ),
    ),
)


SourceClass = Literal["publishable", "supporting", "quarantine"]


@dataclass(frozen=True, slots=True)
class SourcePolicyConfig:
    policy_version: str = POLICY_VERSION
    external_ai_allow: tuple[str, ...] = ("*.md", "**/*.md", "*.markdown", "**/*.markdown")
    external_ai_deny: tuple[str, ...] = (
        "no_external_ai/**",
        "**/no_external_ai/**",
        "private/**",
        "**/private/**",
        "internal/**",
        "**/internal/**",
    )
    central_deny: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    source_class: SourceClass
    publishable: bool
    external_ai_allowed: bool
    reason_code: str
    external_ai_reason: str


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    folded = path.casefold()
    return any(fnmatch.fnmatchcase(folded, pattern.casefold()) for pattern in patterns)


def scan_secret_rule(source_bytes: bytes) -> str | None:
    for name, pattern in _SECRET_RULES:
        if pattern.search(source_bytes):
            return name
    return None


class SourcePolicy:
    """Classify a stable, canonical Markdown snapshot.

    Publish permission and external-model permission are evaluated separately.
    A normal Markdown under the configured root is publishable by default; only
    exceptional or unsafe material is sent to quarantine.
    """

    def __init__(self, config: SourcePolicyConfig | None = None):
        self.config = config or SourcePolicyConfig()

    def evaluate(
        self,
        logical_path: str,
        source_bytes: bytes,
        *,
        boundary_issue: str | None = None,
        structure_valid: bool = True,
        identity_ambiguous: bool = False,
    ) -> PolicyDecision:
        path = PurePosixPath(logical_path)
        name = path.name.casefold()
        parts = tuple(part.casefold() for part in path.parts)

        if boundary_issue is not None:
            return PolicyDecision(
                "quarantine", False, False, boundary_issue, "boundary_not_eligible"
            )
        if _matches(logical_path, self.config.central_deny):
            return PolicyDecision(
                "quarantine", False, False, "central_deny", "central_deny"
            )
        if any(part.startswith("_") for part in parts[:-1]) or any(
            part in {item.casefold() for item in _RESERVED_DIRECTORIES}
            for part in parts[:-1]
        ):
            return PolicyDecision(
                "quarantine", False, False, "reserved_path", "reserved_path"
            )
        if _RESERVED_NAME_RE.search(path.stem):
            return PolicyDecision(
                "quarantine", False, False, "reserved_filename", "reserved_filename"
            )
        secret_rule = scan_secret_rule(source_bytes)
        if secret_rule is not None:
            return PolicyDecision(
                "quarantine",
                False,
                False,
                f"secret_detected:{secret_rule}",
                "secret_detected",
            )
        if identity_ambiguous:
            return PolicyDecision(
                "quarantine", False, False, "identity_ambiguous", "identity_ambiguous"
            )
        if not structure_valid:
            return PolicyDecision(
                "quarantine", False, False, "invalid_structure", "invalid_structure"
            )
        if name in _SUPPORTING_NAMES:
            return PolicyDecision(
                "supporting", False, False, "supporting_content", "supporting_content"
            )

        if _matches(logical_path, self.config.external_ai_deny):
            return PolicyDecision(
                "publishable", True, False, "default_publishable", "blocked_by_path_policy"
            )
        if _matches(logical_path, self.config.external_ai_allow):
            return PolicyDecision(
                "publishable", True, True, "default_publishable", "allowed_by_path_policy"
            )
        # External sending is fail-closed even when deterministic publishing is
        # allowed.  This distinction is important for newly introduced roots.
        return PolicyDecision(
            "publishable", True, False, "default_publishable", "external_ai_undetermined"
        )


__all__ = [
    "POLICY_VERSION",
    "PolicyDecision",
    "SourcePolicy",
    "SourcePolicyConfig",
    "scan_secret_rule",
]
