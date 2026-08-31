"""Read-only local stdio MCP over an authority-verified knowledge mirror."""

from .mirror import (
    AuthorityIdentity,
    FileAuthorityProbe,
    MirrorError,
    MirrorStore,
    build_search_artifact,
)
from .evaluation import (
    IntegratedAcceptanceReport,
    PreregisteredAcceptanceCase,
    ToolChoiceCase,
    ToolChoiceReport,
    ToolTraceEvent,
    evaluate_preregistered_acceptance,
    evaluate_tool_choice,
    load_codex_tool_trace_bytes,
    record_acceptance_preregistration,
)
from .acceptance_runner import (
    FakeArmRun,
    RealArmRun,
    record_real_acceptance_inputs,
    run_fake_acceptance_arm,
    run_real_acceptance_arm,
)
from .service import KnowledgeMCPService

__all__ = [
    "AuthorityIdentity",
    "FileAuthorityProbe",
    "FakeArmRun",
    "RealArmRun",
    "KnowledgeMCPService",
    "IntegratedAcceptanceReport",
    "MirrorError",
    "MirrorStore",
    "PreregisteredAcceptanceCase",
    "ToolChoiceCase",
    "ToolChoiceReport",
    "ToolTraceEvent",
    "build_search_artifact",
    "evaluate_preregistered_acceptance",
    "evaluate_tool_choice",
    "load_codex_tool_trace_bytes",
    "record_acceptance_preregistration",
    "record_real_acceptance_inputs",
    "run_fake_acceptance_arm",
    "run_real_acceptance_arm",
]
