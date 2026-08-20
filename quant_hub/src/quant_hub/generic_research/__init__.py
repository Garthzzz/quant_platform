"""Read-only, snapshot-bound presentation for newly ingested research."""

from .catalog import (
    GenericCatalogError,
    GenericDocumentPage,
    GenericKnowledgeCard,
    GenericResearchCatalog,
)
from .web import generic_research_web

__all__ = [
    "GenericCatalogError",
    "GenericDocumentPage",
    "GenericKnowledgeCard",
    "GenericResearchCatalog",
    "generic_research_web",
]
