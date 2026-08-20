from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from quant_hub.config import Settings
from quant_hub.evidence.replay import run_managed_replay


def main() -> int:
    parser = argparse.ArgumentParser(
        description="在受管隔离子树中回放 Archive Evidence C 五类纵切。"
    )
    parser.add_argument("replay_slug", help="evidence_replay_root 下的安全直接子目录名")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "fixtures"
        / "evidence"
        / "vertical_slice.json",
    )
    arguments = parser.parse_args()
    settings = Settings.default()
    result = run_managed_replay(
        settings,
        replay_slug=arguments.replay_slug,
        fixture_manifest=arguments.manifest.resolve(strict=True),
    )
    payload = asdict(result)
    payload["replay_root"] = str(result.replay_root)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
