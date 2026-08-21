"""Read-only, snapshot-bound presentation for newly ingested research."""

from .catalog import (
    GenericCatalogError,
    GenericDocumentPage,
    GenericKnowledgeCard,
    GenericResearchCatalog,
)
from .web import generic_research_web
from .release import GenericReleaseError, load_generic_catalog_from_release

__all__ = [
    "GenericCatalogError",
    "GenericDocumentPage",
    "GenericKnowledgeCard",
    "GenericResearchCatalog",
    "GenericReleaseError",
    "generic_research_web",
    "load_generic_catalog_from_release",
]
