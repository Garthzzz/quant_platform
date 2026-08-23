"""The sole product authority gate for recovery failure-domain claims.

The authenticated integrated runner and its v2 receipt schema do not exist yet.
Consequently every product consumer must fail here, before reading an evidence
path or performing a mutation.  Legacy v1 facts and attestations remain usable
only by explicitly diagnostic code; they are never an authority fallback.
"""

from __future__ import annotations

from typing import NoReturn


AUTHORITY_SCHEMA = "qrh-recovery-failure-domain-authority/v2"
AUTHORITY_STATUS = "NOT_READY"
AUTHORITY_AVAILABLE = False
AUTHORITY_ERROR_CODE = "FAILURE_DOMAIN_AUTHORITY_NOT_READY"
AUTHORITY_REASON = (
    "authenticated integrated runner v2 is not implemented; legacy v1 "
    "evidence is diagnostic only"
)


class FailureDomainAuthorityNotReady(RuntimeError):
    """Formal failure-domain authority is unavailable in this product build."""

    code = AUTHORITY_ERROR_CODE
    status = AUTHORITY_STATUS
    authority = AUTHORITY_AVAILABLE

    def __init__(self) -> None:
        super().__init__(f"{AUTHORITY_ERROR_CODE}: {AUTHORITY_REASON}")

    def document(self) -> dict[str, object]:
        return failure_domain_authority_status()


def failure_domain_authority_status() -> dict[str, object]:
    """Return the closed, non-authoritative product readiness state."""

    return {
        "schema_version": AUTHORITY_SCHEMA,
        "status": AUTHORITY_STATUS,
        "authority": AUTHORITY_AVAILABLE,
        "error_code": AUTHORITY_ERROR_CODE,
        "reason": AUTHORITY_REASON,
    }


def require_failure_domain_authority() -> NoReturn:
    """Reject before any caller-supplied evidence path can be accessed."""

    raise FailureDomainAuthorityNotReady()


__all__ = [
    "AUTHORITY_AVAILABLE",
    "AUTHORITY_ERROR_CODE",
    "AUTHORITY_SCHEMA",
    "AUTHORITY_STATUS",
    "FailureDomainAuthorityNotReady",
    "failure_domain_authority_status",
    "require_failure_domain_authority",
]
