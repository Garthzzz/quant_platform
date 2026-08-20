"""Versioned deterministic knowledge-ingestion foundation."""

from .chunks import CHUNKER_VERSION, build_chunks
from .compiler import ReferenceCompiler, validate_snapshot
from .contracts import (
    BaseSnapshot,
    Chunk,
    CompileReport,
    DocumentIR,
    DocumentRecord,
    DocumentVersion,
    IRBlock,
    QuarantineItem,
    SourceSpan,
    TombstoneDirective,
)
from .ir import DocumentIRValidationError, IR_PARSER_VERSION, build_document_ir
from .policy import POLICY_VERSION, SourcePolicy, SourcePolicyConfig

__all__ = [
    "BaseSnapshot",
    "CHUNKER_VERSION",
    "Chunk",
    "CompileReport",
    "DocumentIR",
    "DocumentIRValidationError",
    "DocumentRecord",
    "DocumentVersion",
    "IRBlock",
    "IR_PARSER_VERSION",
    "POLICY_VERSION",
    "QuarantineItem",
    "ReferenceCompiler",
    "SourcePolicy",
    "SourcePolicyConfig",
    "SourceSpan",
    "TombstoneDirective",
    "build_chunks",
    "build_document_ir",
    "validate_snapshot",
]
