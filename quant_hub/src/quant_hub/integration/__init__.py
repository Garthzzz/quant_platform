"""Quant Research Hub 跨域编排与幂等事件消费。"""

from .evidence_projection import (
    EvidenceProjectionConsumer,
    EvidenceProjectionError,
    EvidenceProjectionResult,
)
from .incremental_intake import (
    EvidenceDispatchReceipt,
    EvidenceIngestAdapter,
    EvidenceIngestCommand,
    IncrementalIntake,
    IntakeReport,
    IntakeSource,
    LocalSpoolEvidenceAdapter,
)

__all__ = [
    "EvidenceDispatchReceipt",
    "EvidenceIngestAdapter",
    "EvidenceIngestCommand",
    "EvidenceProjectionConsumer",
    "EvidenceProjectionError",
    "EvidenceProjectionResult",
    "IncrementalIntake",
    "IntakeReport",
    "IntakeSource",
    "LocalSpoolEvidenceAdapter",
]
