"""Archive Evidence：论文身份、引用、资源与发布边界。"""

from .database import evidence_connection, initialize_evidence_database
from .expansion import EvidenceExpansionRepository, EvidenceExpansionService
from .ids import citation_id_for_marker, normalize_identifier
from .providers import ArxivAdapter, CrossrefAdapter, ResolutionQuery

__all__ = [
    "citation_id_for_marker",
    "ArxivAdapter",
    "CrossrefAdapter",
    "EvidenceExpansionRepository",
    "EvidenceExpansionService",
    "ResolutionQuery",
    "evidence_connection",
    "initialize_evidence_database",
    "normalize_identifier",
]
