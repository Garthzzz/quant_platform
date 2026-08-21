"""Read-only local stdio MCP over an authority-verified knowledge mirror."""

from .mirror import (
    AuthorityIdentity,
    FileAuthorityProbe,
    MirrorError,
    MirrorStore,
    build_search_artifact,
)
from .evaluation import (
    ToolChoiceCase,
    ToolChoiceReport,
    ToolTraceEvent,
    evaluate_tool_choice,
)
from .service import KnowledgeMCPService

__all__ = [
    "AuthorityIdentity",
    "FileAuthorityProbe",
    "KnowledgeMCPService",
    "MirrorError",
    "MirrorStore",
    "ToolChoiceCase",
    "ToolChoiceReport",
    "ToolTraceEvent",
    "build_search_artifact",
    "evaluate_tool_choice",
]
