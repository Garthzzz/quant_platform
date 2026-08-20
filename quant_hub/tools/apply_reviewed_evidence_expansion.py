from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys


FORMAL_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = FORMAL_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from quant_hub.config import Settings
from quant_hub.evidence.canonicalization import (
    MethodOriginCandidateInput,
    ReviewedEvidenceCanonicalizationService,
    load_reviewed_manifest,
)


def _load_derivations(path: Path) -> tuple[MethodOriginCandidateInput, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "qrh-method-origin-candidate-derivations/v1":
        raise ValueError("unsupported method-origin derivation manifest")
    return tuple(MethodOriginCandidateInput.model_validate(row) for row in payload["items"])


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Plan or atomically apply an explicitly reviewed Evidence canonicalization. "
            "Without --apply this command never opens or creates a runtime database."
        )
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--manifest", type=Path, help="Reviewed canonicalization JSON manifest.")
    mode.add_argument(
        "--method-origin-derivations",
        type=Path,
        help="Create separate paper candidates beside rejected method-name candidates.",
    )
    parser.add_argument("--project-root", type=Path, default=FORMAL_ROOT.parent)
    parser.add_argument("--var-root", type=Path)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write only to the explicitly selected --var-root Evidence database.",
    )
    args = parser.parse_args()

    if args.manifest is not None:
        manifest = load_reviewed_manifest(args.manifest.resolve())
        static_plan = ReviewedEvidenceCanonicalizationService.static_plan(manifest)
        if not args.apply:
            print(json.dumps({"mode": "plan_only", **static_plan}, ensure_ascii=False, indent=2))
            return 0
    else:
        derivations = _load_derivations(args.method_origin_derivations.resolve())
        static_plan = {
            "schema_version": "qrh-method-origin-candidate-derivations/v1",
            "item_count": len(derivations),
            "items": [
                {
                    **value.model_dump(mode="json"),
                    "normalized_identifier": value.normalized_identifier,
                    "resolved_derived_source_candidate_id": value.resolved_derived_source_candidate_id,
                }
                for value in derivations
            ],
        }
        if not args.apply:
            print(json.dumps({"mode": "plan_only", **static_plan}, ensure_ascii=False, indent=2))
            return 0

    if args.var_root is None:
        parser.error("--apply requires an explicit --var-root")
    settings = Settings.default(
        project_root=args.project_root.resolve(),
        var_root=args.var_root.resolve(),
    )
    service = ReviewedEvidenceCanonicalizationService(settings)
    if args.manifest is not None:
        result = service.apply(manifest)
        output = {
            "mode": "applied",
            "manifest_sha256": result.manifest_sha256,
            "items": [asdict(item) for item in result.items],
        }
    else:
        result = service.prepare_method_origin_candidates(derivations)
        output = {
            "mode": "applied_method_origin_derivations",
            "items": [asdict(item) for item in result],
        }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

