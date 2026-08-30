"""Host-side CLI for one sealed exact-D operational tooling update."""

from __future__ import annotations

import argparse
import json
from pathlib import PureWindowsPath

from .publish_adapters import OpenSSHToolingUpdater, VMConfig


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-alias", required=True)
    parser.add_argument("--target-address", required=True)
    parser.add_argument("--vm-root", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = VMConfig(
            ssh_alias=args.ssh_alias,
            target_address=args.target_address,
            root=PureWindowsPath(args.vm_root),
        )
        result = OpenSSHToolingUpdater(config).invoke(
            vm_root=config.root,
            release_id=args.release_id,
            release_manifest_sha256=args.release_manifest_sha256,
            attempt_id=args.attempt_id,
        )
    except Exception as error:
        print(
            json.dumps(
                {
                    "schema_version": "qrh-tooling-update-host-error/v1",
                    "status": "error",
                    "error_type": type(error).__name__,
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
