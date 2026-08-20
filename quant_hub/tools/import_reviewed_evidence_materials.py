from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
SOURCE_ROOT = FORMAL_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from quant_hub.config import Settings
from quant_hub.evidence.reviewed_material_importer import (
    ReviewedMaterialImporter,
    ReviewedMaterialSources,
)


def main() -> int:
    crossref_root = WORKSPACE_ROOT / "project_state" / "workers" / "crossref_identity_review"
    arxiv_root = WORKSPACE_ROOT / "project_state" / "workers" / "arxiv_expansion_materials"
    parser = argparse.ArgumentParser(
        description=(
            "Validate or import reviewed Crossref/arXiv material through the Evidence "
            "resolution, rights, acquisition, reading, and canonicalization services. "
            "The default plan mode does not open a database."
        )
    )
    parser.add_argument(
        "--crossref-decisions",
        type=Path,
        action="append",
        default=None,
    )
    parser.add_argument(
        "--crossref-rights",
        type=Path,
        default=crossref_root / "rights_resource_offers.jsonl",
    )
    parser.add_argument(
        "--crossref-identity-verdicts",
        type=Path,
        default=(
            WORKSPACE_ROOT
            / "project_state"
            / "workers"
            / "independent_identity_verifier"
            / "item_verdicts.jsonl"
        ),
    )
    parser.add_argument(
        "--crossref-fulltext",
        type=Path,
        default=(
            WORKSPACE_ROOT
            / "project_state"
            / "workers"
            / "u055_open_pdf_acquisition"
            / "manifest.json"
        ),
    )
    parser.add_argument(
        "--arxiv-materials", type=Path, default=arxiv_root / "manifest.json"
    )
    parser.add_argument(
        "--arxiv-readings", type=Path, default=arxiv_root / "reading_records.json"
    )
    parser.add_argument(
        "--arxiv-total-delivery",
        type=Path,
        default=arxiv_root / "total_delivery_manifest.json",
    )
    parser.add_argument(
        "--arxiv-resolution-seed",
        type=Path,
        default=arxiv_root / "total_resolution_seed.json",
    )
    parser.add_argument(
        "--arxiv-method-origin-inputs",
        type=Path,
        default=arxiv_root / "identity_review" / "method_origin_candidate_inputs.json",
    )
    parser.add_argument(
        "--arxiv-independent-verdict",
        type=Path,
        default=(
            WORKSPACE_ROOT
            / "project_state"
            / "workers"
            / "independent_arxiv_verifier_v2"
            / "verdict_v4.json"
        ),
    )
    parser.add_argument(
        "--reconciliation-overrides",
        type=Path,
        help=(
            "Explicit reviewed allow/deny decisions. Built-in version-family deny rules "
            "remain fail-closed unless an independent_verifier allow is supplied."
        ),
    )
    parser.add_argument(
        "--include-source-candidate",
        action="append",
        default=[],
        help="Limit an isolated replay/test to selected source candidate IDs.",
    )
    parser.add_argument("--project-root", type=Path, default=WORKSPACE_ROOT)
    parser.add_argument("--var-root", type=Path)
    parser.add_argument("--review-id", default="reviewed-evidence-expansion-20260715")
    parser.add_argument("--reviewed-by", default="Quant Research Hub reviewed-material audit")
    parser.add_argument("--reviewed-at", default="2026-07-15T00:00:00Z")
    parser.add_argument(
        "--provenance-urn", default="qrh:evidence:reviewed-material-import:20260715"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write only to the explicitly selected --var-root runtime.",
    )
    args = parser.parse_args()

    sources = ReviewedMaterialSources(
        crossref_decisions=tuple(
            path.resolve()
            for path in (
                args.crossref_decisions
                or [crossref_root / "accepted_decisions.jsonl"]
            )
        ),
        crossref_rights_manifest=args.crossref_rights.resolve(),
        arxiv_materials_manifest=args.arxiv_materials.resolve(),
        arxiv_reading_records=args.arxiv_readings.resolve(),
        reconciliation_overrides=(
            args.reconciliation_overrides.resolve()
            if args.reconciliation_overrides is not None
            else None
        ),
        crossref_identity_verdicts=args.crossref_identity_verdicts.resolve(),
        crossref_fulltext_manifest=args.crossref_fulltext.resolve(),
        arxiv_total_delivery_manifest=args.arxiv_total_delivery.resolve(),
        arxiv_resolution_seed=args.arxiv_resolution_seed.resolve(),
        arxiv_method_origin_inputs=args.arxiv_method_origin_inputs.resolve(),
        arxiv_independent_verdict=args.arxiv_independent_verdict.resolve(),
    )
    include = (
        frozenset(args.include_source_candidate)
        if args.include_source_candidate
        else None
    )
    if not args.apply:
        print(
            json.dumps(
                ReviewedMaterialImporter.static_plan(
                    sources, include_source_candidates=include
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.var_root is None:
        parser.error("--apply requires an explicit --var-root")

    settings = Settings.default(
        project_root=args.project_root.resolve(), var_root=args.var_root.resolve()
    )
    result = ReviewedMaterialImporter(settings).apply(
        sources,
        review_id=args.review_id,
        reviewed_by=args.reviewed_by,
        reviewed_at=args.reviewed_at,
        provenance_urn=args.provenance_urn,
        include_source_candidates=include,
    )
    print(json.dumps({"mode": "applied", **result.as_dict()}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
