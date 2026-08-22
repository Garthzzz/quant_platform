"""Zero-network CLI for the public-synthetic DS campaign preregistration."""

from __future__ import annotations

import argparse
from typing import Sequence

from .contracts import canonical_json
from .ds_review import (
    DossierPolicyError,
    ProviderPin,
    ROUND_IDS,
    default_synthetic_dossier,
    dry_run_receipt,
    prepare_campaign,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m quant_hub.knowledge.ds_review_cli")
    parser.add_argument(
        "--expected-system-fingerprint",
        required=True,
        help="pre-approved fixed provider fingerprint; never discovered by this command",
    )
    parser.add_argument(
        "--round",
        choices=("all", *ROUND_IDS),
        default="all",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        pin = ProviderPin.create(
            expected_system_fingerprint=arguments.expected_system_fingerprint
        )
        campaign = prepare_campaign(default_synthetic_dossier(), pin=pin)
        selected = ROUND_IDS if arguments.round == "all" else (arguments.round,)
        receipts = [
            dry_run_receipt(campaign, round_id=round_id)
            for round_id in selected
        ]
        value = {
            "schema_version": "qrh-ds-architecture-review-dry-run-bundle/v2",
            "status": "dry_run_no_network",
            "campaign_id": campaign.manifest.campaign_id,
            "campaign_manifest_sha256": campaign.manifest.manifest_sha256,
            "receipts": receipts,
            "network_calls": 0,
            "authority": "ADVISORY_ONLY",
        }
        print(canonical_json(value))
        return 0
    except (DossierPolicyError, ValueError) as error:
        print(
            canonical_json(
                {
                    "schema_version": "qrh-ds-architecture-review-cli-error/v1",
                    "status": "error",
                    "error": str(error),
                    "network_calls": 0,
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
