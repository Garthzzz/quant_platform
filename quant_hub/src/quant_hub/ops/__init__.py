"""Quant Research Hub 运维与发布合同。"""

_IDENTITY_EXPORTS = (
    "IdentityContractError",
    "IdentityGraphReport",
    "authorize_receipt_append",
    "canonical_manifest_bytes",
    "lint_identity_graph",
    "manifest_sha256",
    "validate_active_release",
    "validate_receipt",
    "validate_release_manifest",
)

_DEPLOYMENT_EXPORTS = (
    "ActiveAuthorityCorrupt",
    "CandidateValidationError",
    "DeploymentController",
    "DeploymentFailed",
    "DeploymentLayout",
    "DeploymentLocked",
    "DeploymentResult",
)

__all__ = [
    *_IDENTITY_EXPORTS,
    *_DEPLOYMENT_EXPORTS,
]


def __getattr__(name: str) -> object:
    """Preserve the public ops API without eager application imports."""

    if name in _IDENTITY_EXPORTS:
        from .release_identity import (
            IdentityContractError,
            IdentityGraphReport,
            authorize_receipt_append,
            canonical_manifest_bytes,
            lint_identity_graph,
            manifest_sha256,
            validate_active_release,
            validate_receipt,
            validate_release_manifest,
        )

        return {
            "IdentityContractError": IdentityContractError,
            "IdentityGraphReport": IdentityGraphReport,
            "authorize_receipt_append": authorize_receipt_append,
            "canonical_manifest_bytes": canonical_manifest_bytes,
            "lint_identity_graph": lint_identity_graph,
            "manifest_sha256": manifest_sha256,
            "validate_active_release": validate_active_release,
            "validate_receipt": validate_receipt,
            "validate_release_manifest": validate_release_manifest,
        }[name]
    if name in _DEPLOYMENT_EXPORTS:
        from .deployment import (
            ActiveAuthorityCorrupt,
            CandidateValidationError,
            DeploymentController,
            DeploymentFailed,
            DeploymentLayout,
            DeploymentLocked,
            DeploymentResult,
        )

        return {
            "ActiveAuthorityCorrupt": ActiveAuthorityCorrupt,
            "CandidateValidationError": CandidateValidationError,
            "DeploymentController": DeploymentController,
            "DeploymentFailed": DeploymentFailed,
            "DeploymentLayout": DeploymentLayout,
            "DeploymentLocked": DeploymentLocked,
            "DeploymentResult": DeploymentResult,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
