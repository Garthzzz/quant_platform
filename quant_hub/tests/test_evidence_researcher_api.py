from __future__ import annotations

import json
from pathlib import Path
import re

from flask import Flask

from quant_hub.config import Settings
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.service import EvidenceQueryService, _researcher_excerpt_text
from quant_hub.evidence.web import create_evidence_blueprint
from tests.helpers import latest_activated_reviewed_delivery


FORBIDDEN_KEY_PARTS = (
    "verification",
    "fact_boundary",
    "provenance",
    "sha",
    "bytes",
    "rights",
    "ledger",
    "urn",
    "canonical_path",
    "locator",
    "metadata_review",
    "reading_task",
    "category",
)

EXPECTED_WITHOUT_ARCHIVE_RELATIONS = {
    "paper_30fc1eb5858545d22e4b3ccab5b1febb",
    "paper_40578850ccddcd8c60c8e89c40d37efe",
    "paper_41661edf682fcaf903224dadd6371a40",
    "paper_9f702d636ede7e2b1132f621b2c893e6",
    "paper_b943baa5da42b80c58821cde981cb662",
    "paper_bd8f17b241dc862944cd91cdf4fc6e84",
    "paper_cfef40f2a00de557070f81d98688911e",
    "paper_e607be627bb39f7a981380b9f3166c35",
}


def _walk_keys(value: object) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            keys.extend(_walk_keys(nested))
    return keys


def _latest_reviewed_var(project_root: Path) -> Path:
    return latest_activated_reviewed_delivery(project_root)


def test_researcher_excerpt_omits_two_real_publisher_footers_without_mutating_source() -> None:
    ledroit_wolf = (
        "Extensive Monte Carlo confirm that the asymptotic results tend to hold "
        "well in finite sample. r 2003 Elsevier Inc. All rights reserved. "
        "AMS 2000 subject classifications: 62H12; 62C12; 62J07"
    )
    roc = (
        "The purpose of this article is to serve as an introduction to ROC "
        "graphs and as a guide for using them in research. 2005 Elsevier B.V. "
        "All rights reserved."
    )
    original = (ledroit_wolf, roc)

    cleaned = tuple(_researcher_excerpt_text(value) for value in original)

    assert cleaned[0].endswith("well in finite sample.")
    assert cleaned[1].endswith("using them in research.")
    assert all("all rights reserved" not in value.casefold() for value in cleaned)
    assert original[0].endswith("62H12; 62C12; 62J07")
    assert original[1].endswith("All rights reserved.")


def test_researcher_excerpt_cuts_reviewed_pdf_cover_and_two_column_artifacts() -> None:
    stylized_facts = (
        "We present a set of stylized empirical facts and examine the statistical "
        "problems encountered in each case. Although statistical properties of "
        "prices of stocks and Our goal is to let data speak. "
        "1469-7688/01/020223+14$30.00 © 2001 IOP Publishing Ltd"
    )
    chinese_factor_zoo = (
        "Our out-of-sample performance remains economically significant after "
        "transaction costs. DOI: https://doi.org/10.1016/j.jfineco.2021.08.017 "
        "Posted at the Zurich Open Repository and Archive. The following work is "
        "licensed under a Creative Commons license. © 2021 The Author(s). "
        "Published by Elsevier B.V. This is an open access article under the CC BY "
        "license (http://creativecommons.org/licenses/by/4.0/)"
    )

    cleaned_stylized = _researcher_excerpt_text(stylized_facts)
    cleaned_factor_zoo = _researcher_excerpt_text(chinese_factor_zoo)

    assert cleaned_stylized.endswith("encountered in each case.")
    assert cleaned_factor_zoo.endswith("after transaction costs.")
    serialized = (cleaned_stylized + cleaned_factor_zoo).casefold()
    assert "iop publishing" not in serialized
    assert "published by elsevier" not in serialized
    assert "creative commons" not in serialized


def test_all_78_public_detail_api_payloads_use_the_researcher_allowlist() -> None:
    project_root = Path(__file__).resolve().parents[2]
    var_root = _latest_reviewed_var(project_root)
    settings = Settings.default(
        project_root=project_root,
        archive_root=project_root / "reference" / "archive",
        var_root=var_root,
        # The immutable reviewed corpus is read with the current migration
        # contract, including the external research-workspace domain added
        # after the activated V34 runtime was assembled.
        migration_root=project_root / "quant_hub" / "migrations" / "platform",
    )
    app = Flask(
        __name__,
        template_folder=str(
            project_root / "quant_hub" / "src" / "quant_hub" / "web" / "templates"
        ),
    )
    app.config.update(TESTING=True)
    app.register_blueprint(create_evidence_blueprint(settings))
    client = app.test_client()
    archive_index = EvidenceQueryService(settings)._archive_link_index()
    published_documents = {
        (str(target["research_id"]), str(target["document_id"])): {
            "document_anchor": f"document-{target['document_id']}",
            "section_anchors": {
                str(section.get("anchor_id") or "")
                for section in target.get("sections") or []
                if isinstance(section, dict)
            },
        }
        for target in archive_index.values()
        if target.get("research_id") and target.get("document_id")
    }
    with evidence_connection(settings) as connection:
        paper_ids = [
            str(row[0])
            for row in connection.execute("SELECT paper_id FROM paper ORDER BY paper_id")
        ]
    assert len(paper_ids) == 78
    catalogue_response = client.get("/api/v1/evidence/papers?limit=100")
    assert catalogue_response.status_code == 200
    catalogue = catalogue_response.get_json()["data"]
    assert catalogue["total"] == 78
    catalogue_relation_coverage = {
        str(paper["paper_id"]): bool(
            paper["dossier_coverage"]["archive_relations"]
        )
        for paper in catalogue["papers"]
    }
    observed_without_relations = {
        paper_id
        for paper_id, covered in catalogue_relation_coverage.items()
        if not covered
    }
    assert EXPECTED_WITHOUT_ARCHIVE_RELATIONS <= observed_without_relations

    allowed_top_level = {
        "paper_id",
        "title",
        "publication_date",
        "venue",
        "authors",
        "institutions",
        "external_links",
        "local_resources",
        "abstract_excerpts",
        "core_conclusions",
        "chinese_presentation",
        "archive_relations",
        "archive_core_relations",
        "archive_reference_relations",
        "archive_relation_scope",
        "evidence_coverage",
    }
    relation_count = 0
    papers_with_relations = 0
    for paper_id in paper_ids:
        response = client.get(f"/api/v1/evidence/papers/{paper_id}")
        assert response.status_code == 200, paper_id
        data = response.get_json()["data"]
        assert set(data) == allowed_top_level
        for key in _walk_keys(data):
            lowered = key.casefold()
            assert not any(part in lowered for part in FORBIDDEN_KEY_PARTS), (
                paper_id,
                key,
            )
        serialized = json.dumps(data, ensure_ascii=False).casefold()
        assert "all rights reserved" not in serialized
        assert "iop publishing ltd" not in serialized
        assert "published by elsevier" not in serialized
        assert "creative commons:" not in serialized
        assert "open access article under the cc by" not in serialized
        display_relations = (
            data["archive_core_relations"] or data["archive_reference_relations"]
        )
        assert bool(display_relations) == catalogue_relation_coverage[paper_id]
        if display_relations:
            papers_with_relations += 1
        for relation in display_relations:
            relation_count += 1
            assert relation["document_title"] != "研究概览"
            assert relation["source_url"].startswith("/research/")
            assert "/documents/" in relation["source_url"]
            match = re.fullmatch(
                r"/research/([^/]+)/documents/([^#]+)#(.+)",
                relation["source_url"],
            )
            assert match is not None
            target = published_documents[(match.group(1), match.group(2))]
            assert match.group(3) == target["document_anchor"] or match.group(
                3
            ) in target["section_anchors"]
            assert not any(
                suffix in json.dumps(relation, ensure_ascii=False).casefold()
                for suffix in (".tex", ".bib", "backup", "canonical_path")
            )
    assert papers_with_relations == sum(catalogue_relation_coverage.values())
    assert relation_count >= papers_with_relations
