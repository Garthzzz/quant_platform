from __future__ import annotations

import argparse
import json
from pathlib import Path

from quant_hub.config import Settings
from quant_hub.evidence.replay import run_managed_bulk_replay


def main() -> int:
    parser = argparse.ArgumentParser(
        description="在受管隔离子树内回放 Archive Evidence 全量数据包。"
    )
    parser.add_argument("replay_slug", help="受管 replay 根下的新 direct-child slug")
    parser.add_argument(
        "--package",
        type=Path,
        default=Path("project_state/workers/e_evidence_bulk_data"),
    )
    parser.add_argument(
        "--normalized-manifest",
        type=Path,
        default=Path("quant_hub/fixtures/evidence/normalized_resource_manifest.jsonl"),
    )
    arguments = parser.parse_args()
    settings = Settings.default(project_root=Path.cwd())
    result = run_managed_bulk_replay(
        settings,
        replay_slug=arguments.replay_slug,
        package_root=arguments.package,
        normalized_manifest_path=arguments.normalized_manifest,
    )
    print(
        json.dumps(
            {
                "replay_slug": result.replay_slug,
                "replay_root": str(result.replay_root),
                "schema_hash": result.schema_hash,
                "inventory_sha256": result.inventory_sha256,
                "inventory_bytes": result.inventory_bytes,
                "candidate_inventory_sha256": result.candidate_inventory_sha256,
                "candidate_inventory_bytes": result.candidate_inventory_bytes,
                "evidence_release_id": result.evidence_release_id,
                "release_snapshot_urn": result.release_snapshot_urn,
                "active_revision": result.active_revision,
                "release_created": result.release_created,
                "resource_count": result.resource_count,
                "counts": result.counts,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
